import posix

const
  KVM_IO_MAGIC_BYTE: culong = 0xAE
  KVM_NR_INTERRUPTS = 256
  GUEST_MEM_SIZE = 2 * 1024 * 1024
  KVM_EXIT_IO_OUT: uint32 = 1
  KVM_EXIT_IO: uint32 = 2
  KVM_EXIT_HLT: uint32 = 5

proc ioctl(fd: cint, request: culong, arg: culong = 0): cint
  {.importc, varargs, header: "<sys/ioctl.h>".}

proc ioxctl(fd: cint, request: culong, arg: pointer): cint
  {.importc: "ioctl", header: "<sys/ioctl.h>".}

proc kvm_io(nr: culong): culong =
  return (KVM_IO_MAGIC_BYTE shl 8) or nr

proc kvm_ior(nr: culong, size: culong): culong =
  return (2.culong shl 30) or (size shl 16) or kvm_io(nr)

proc kvm_iow(nr: culong, size: culong): culong =
  return (1.culong shl 30) or (size shl 16) or kvm_io(nr)

type KvmUserspaceMemoryRegion {.packed.} = object # needs to exactly match the c array
  slot: uint32
  flags: uint32
  guest_addr: uint64
  memory_size: uint64
  userspace_addr: uint64

type KvmRunIo {.packed.} = object
  direction: uint8
  size: uint8
  port: uint16
  count: uint32
  data_offset: uint64

type KvmRunState {.packed.} = object
  request_interrupt_window: uint8
  immediate_exit: uint8
  padding1: array[6, uint8]
  exit_reason: uint32
  ready_for_interrupt_injection: uint8
  if_flag: uint8
  flags: uint16
  cr8: uint64
  apic_base: uint64
  io: KvmRunIo

type KvmRegs {.packed.} = object
  rax, rbx, rcx, rdx: uint64
  rsi, rdi, rsp, rbp: uint64
  r8,  r9,  r10, r11: uint64
  r12, r13, r14, r15: uint64
  rip, rflags: uint64

type KvmSegment {.packed.} = object
  base: uint64
  limit: uint32
  selector: uint16
  seg_type: uint8
  present, dpl, db, s, l, g, avl: uint8
  unusable: uint8
  padding: uint8

type KvmDtable {.packed.} = object
  base: uint64
  limit: uint16
  padding: array[3, uint16]

type KvmSregs {.packed.} = object
  cs, ds, es, fs, gs, ss: KvmSegment
  tr, ldt: KvmSegment
  gdt, idt: KvmDtable
  cr0, cr2, cr3, cr4, cr8: uint64
  efer: uint64
  apic_base: uint64
  interrupt_bitmap: array[(KVM_NR_INTERRUPTS + 63) div 64, uint64]

type Vm* = ref object
  kvm_fd: cint
  vm_fd: cint
  vcpu_fd: cint
  guest_mem: pointer
  guest_mem_size: int
  raw_kr: pointer
  mmap_size: cint

const
  KVM_GET_API_VERSION = kvm_io(0x00)
  KVM_CREATE_VM = kvm_io(0x01)
  KVM_GET_VCPU_MMAP_SIZE = kvm_io(0x04)
  KVM_CREATE_VCPU = kvm_io(0x41)
  KVM_SET_USER_MEMORY_REGION = kvm_iow(0x46, 32)
  KVM_RUN = kvm_io(0x80)
  KVM_SET_REGS = kvm_iow(0x82, sizeof(KvmRegs).culong)
  KVM_GET_SREGS = kvm_ior(0x83, sizeof(KvmSregs).culong)
  KVM_SET_SREGS = kvm_iow(0x84, sizeof(KvmSregs).culong)

proc setupMem(vm: Vm) =
  var region = KvmUserspaceMemoryRegion(
    slot: 0,
    flags: 0,
    guest_addr: 0x0000'u64,
    memory_size: vm.guest_mem_size.uint64,
    userspace_addr: cast[uint64](vm.guest_mem)
  )
  if ioxctl(vm.vm_fd, KVM_SET_USER_MEMORY_REGION, addr region) < 0:
    echo "KVM_SET_USER_MEMORY_REGION: ", strerror(errno)
    quit(1)

proc setupRegs*(vm: Vm) =
  var regs: KvmRegs
  var sregs: KvmSregs
  if ioxctl(vm.vcpu_fd, KVM_GET_SREGS, addr sregs) < 0:
    echo "KVM_GET_SREGS: ", strerror(errno)
    quit(1)

  sregs.cs.base = 0
  sregs.cs.selector = 0
  if ioxctl(vm.vcpu_fd, KVM_SET_SREGS, addr sregs) < 0:
    echo "KVM_SET_SREGS: ", strerror(errno)
    quit(1)

  regs.rip = 0
  regs.rflags = 2
  if ioxctl(vm.vcpu_fd, KVM_SET_REGS, addr regs) < 0:
    echo "KVM_SET_REGS: ", strerror(errno)
    quit(1)

proc loadCode*(vm: Vm, code: openArray[uint8]) =
  let guest_mem_access = cast[ptr UncheckedArray[uint8]](vm.guest_mem)
  for i, byte in code:
    guest_mem_access[i] = byte

proc run*(vm: Vm) =
  let kvm_runner = cast[ptr KvmRunState](vm.raw_kr)
  while true:
    if ioctl(vm.vcpu_fd, KVM_RUN) < 0:
      echo "KVM_RUN: ", strerror(errno)
      quit(1)
    case kvm_runner.exit_reason:
      of KVM_EXIT_HLT:
        echo "guest halted"
        break
      of KVM_EXIT_IO:
        if kvm_runner.io.port == 0x3F8'u16 and kvm_runner.io.direction == 1'u8: # 0x3F8 is io port
          stdout.write(char(cast[ptr uint8](cast[uint64](vm.raw_kr) + kvm_runner.io.data_offset)[]))
          echo "" # adds newline to out
      else:
        echo "unhandled exit: ", kvm_runner.exit_reason
        break

proc destroy*(vm: Vm) =
  discard posix.munmap(vm.guest_mem, vm.guest_mem_size)
  discard posix.munmap(vm.raw_kr, vm.mmap_size.int)
  discard posix.close(vm.vm_fd)
  discard posix.close(vm.kvm_fd)
  discard posix.close(vm.vcpu_fd)

proc newVm*(): Vm =
  result = Vm()
  result.kvm_fd = posix.open("/dev/kvm", O_RDWR)
  result.vm_fd = ioctl(result.kvm_fd, KVM_CREATE_VM)
  result.vcpu_fd = ioctl(result.vm_fd, KVM_CREATE_VCPU)
  result.guest_mem_size = GUEST_MEM_SIZE
  result.mmap_size = ioctl(result.kvm_fd, KVM_GET_VCPU_MMAP_SIZE)
  result.guest_mem = posix.mmap(
    nil,
    GUEST_MEM_SIZE,
    PROT_READ or PROT_WRITE,
    MAP_PRIVATE or MAP_ANONYMOUS,
    -1,
    0
  )
  result.raw_kr = posix.mmap(
    nil,
    result.mmap_size,
    PROT_READ or PROT_WRITE,
    MAP_SHARED,
    result.vcpu_fd,
    0
  )
  result.setupMem()
