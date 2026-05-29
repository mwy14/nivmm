import posix

const KVM_IO_MAGIC_BYTE: culong = 0xAE

proc ioctl(fd: cint, request: culong, arg: culong = 0): cint
  {.importc, varargs, header: "<sys/ioctl.h>".}

proc ioxctl(fd: cint, request: culong, arg: pointer): cint
  {.importc: "ioctl", header: "<sys/ioctl.h>".}

proc kvm_io(nr: culong): culong =
  return (KVM_IO_MAGIC_BYTE shl 8) or nr

proc kvm_iow(nr: culong, size: culong): culong =
  return (1.culong shl 30) or (size shl 16) or kvm_io(nr)


const
  KVM_GET_API_VERSION = kvmIo(0x00)
  KVM_CREATE_VM = kvmIo(0x01)
  KVM_SET_USER_MEMORY_REGION = kvmIow(0x46, 32)


type kvm_userspace_memory_region {.packed.} = object # needs to exactly match the c array
  slot: uint32
  flags: uint32
  guest_addr: uint64
  memory_size: uint64
  userspace_addr: uint64

const GUEST_MEM_SIZE = 2 * 1024 * 1024

proc main() =
  let kvmFd = posix.open("/dev/kvm", O_RDWR)
  if kvmFd < 0:
    echo "Cannot open /dev/kvm — check groups"
    quit(1)

  let vmFd = ioctl(kvmFd, KVM_CREATE_VM)
  if vmFd < 0:
    echo "KVM_CREATE_VM: ", strerror(errno)
    quit(1)
  echo "vm_fd: ", vmFd

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

  var region = kvm_userspace_memory_region(
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

  discard posix.munmap(guestMem, GUEST_MEM_SIZE)
  discard posix.close(vmFd)
  discard posix.close(kvmFd)

main()
