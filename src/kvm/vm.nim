import posix

const
  KVM_IO_MAGIC_BYTE: culong = 0xAE
  KVM_NR_INTERRUPTS = 256
  GUEST_MEM_SIZE = 128 * 1024 * 1024 #128MB
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
  uart_lcr: uint8

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

proc strToCode*(msg: string): seq[uint8] =
  result = @[0xBA'u8, 0xF8, 0x03] # mov dx - 0x3F8
  for c in msg:
    result.add(@[0xB0'u8, uint8(c), 0xEE])
  result.add(0xF4'u8) #hlt byte

proc loadKernel*(vm: Vm, path: string) =
  let data = readFile(path)
  let setup_sects = uint8(data[0x1F1])
  let kernel_offset = (setup_sects + 1) * 512
  echo "kernel starts at byte: ", kernel_offset

  let data_ptr = cast[ptr uint8](cast[uint64](vm.guest_mem) + 0x100000)
  let kernel_ptr = unsafeAddr(data[kernel_offset])
  let kernel_size = data.len - int(kernel_offset)

  copyMem(data_ptr, kernel_ptr, kernel_size)

  let source = "console=ttyS0 noapic nokaslr\0"
  let src_ptr = unsafeAddr(source[0])
  let cmd_ptr = cast[ptr uint8](cast[uint64](vm.guest_mem) + 0x20000)
  let cmd_size = source.len

  copyMem(cmd_ptr, src_ptr, cmd_size)

  let boot_params_ptr = cast[ptr uint8](cast[uint64](vm.guest_mem) + 0x10000)
  let boot_params = cast[ptr UncheckedArray[uint8]](boot_params_ptr)
  zeroMem(boot_params_ptr, 4096) # clear page
  copyMem(addr boot_params[0x1F1], unsafeAddr(data[0x1F1]), 128)

  boot_params[0x210] = 0xFF'u8 # type of loader
  boot_params[0x211] = 0x81'u8 # load flags
  cast[ptr uint16](addr boot_params[0x222])[] = 0xFE00'u16  # heap end ptr
  cast[ptr uint32](addr boot_params[0x226])[] = 0x20000'u32 # cmd line ptr

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
        case kvm_runner.io.direction:
          of 0'u8: #guest read
            let data_ptr = cast[ptr uint8](cast[uint64](vm.raw_kr) + kvm_runner.io.data_offset)
            data_ptr[] = case kvm_runner.io.port
              of 0x3FD'u16: 0x60'u8 # write 0x60 to data_offest
              of 0x3FA'u16: 0xC1'u8 # write 0xC1 to data_offset
              else: 0x00'u8 # ingore, do not write
            continue
          of 1'u8: #guest write
            let data = cast[ptr uint8](cast[uint64](vm.raw_kr) + kvm_runner.io.data_offset)[]
            case kvm_runner.io.port
              of 0x3F8: # print byte stored
                if (vm.uart_lcr and 0x80'u8) == 0:
                  stdout.write(char(data))
              of 0x3FB: # write byte to local uart lcr ref
                vm.uart_lcr = data
              else:
                echo "unknown port: ", kvm_runner.io.port
                discard
          else:
            echo "unknown direction: ", kvm_runner.io.direction
            continue
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
