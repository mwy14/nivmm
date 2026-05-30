import posix

const
  KVM_IO_MAGIC_BYTE: culong = 0xAE
  KVM_NR_INTERRUPTS = 256
  GUEST_MEM_SIZE = 2 * 1024 * 1024

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

type KvmRun {.packed.} = object
  request_interrupt_window: uint8
  immediate_exit: uint8
  padding1: array[6, uint8]
  exit_reason: uint32

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


const

  KVM_GET_API_VERSION = kvm_io(0x00)
  KVM_CREATE_VM = kvm_io(0x01)
  KVM_GET_VCPU_MMAP_SIZE = kvm_io(0x04)
  KVM_CREATE_VCPU = kvm_io(0x41)
  KVM_SET_USER_MEMORY_REGION = kvm_iow(0x46, 32)
  KVM_SET_REGS = kvm_iow(0x82, sizeof(KvmRegs).culong)
  KVM_GET_SREGS = kvm_ior(0x83, sizeof(KvmSregs).culong)
  KVM_SET_SREGS = kvm_iow(0x84, sizeof(KvmSregs).culong)

proc main() =
  let kvm_fd = posix.open("/dev/kvm", O_RDWR)
  if kvm_fd < 0:
    echo "Cannot open /dev/kvm — check groups"
    quit(1)

  let vm_fd = ioctl(kvm_fd, KVM_CREATE_VM)
  if vm_fd < 0:
    echo "KVM_CREATE_VM: ", strerror(errno)
    quit(1)
  echo "vm_fd: ", vm_fd

  let guest_mem: pointer = posix.mmap(
    nil,
    GUEST_MEM_SIZE,
    PROT_READ or PROT_WRITE,
    MAP_PRIVATE or MAP_ANONYMOUS,
    -1,
    0
  )
  if guest_mem == MAP_FAILED:
    echo "mmap: ", strerror(errno)
    quit(1)

  var region = KvmUserspaceMemoryRegion(
    slot: 0,
    flags: 0,
    guest_addr: 0x0000'u64,
    memory_size: GUEST_MEM_SIZE.uint64,
    userspace_addr: cast[uint64](guest_mem)
  )
  if ioxctl(vmFd, KVM_SET_USER_MEMORY_REGION, addr region) < 0:
    echo "KVM_SET_USER_MEMORY_REGION: ", strerror(errno)
    quit(1)

  echo "guest RAM ready: ", GUEST_MEM_SIZE, " bytes\n"

  let vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU)
  if vcpu_fd < 0:
    echo "KVM_CREATE_VCPU: ", strerror(errno)
    quit(1)
  echo "vcpu_fd: ", vcpu_fd

  let mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE)

  let raw_kr: pointer = posix.mmap(
    nil,
    mmap_size,
    PROT_READ or PROT_WRITE,
    MAP_SHARED,
    vcpu_fd,
    0
  )

  echo "sizeof KvmSregs: ", sizeof(KvmSregs)
  echo "sizeof KvmRegs:  ", sizeof(KvmRegs)

  let kvm_run = cast[ptr KvmRun](raw_kr)
  echo kvm_run.exit_reason

  discard posix.munmap(guest_mem, GUEST_MEM_SIZE)
  discard posix.munmap(raw_kr, mmap_size)
  discard posix.close(vm_fd)
  discard posix.close(kvm_fd)
  discard posix.close(vcpu_fd)

main()
