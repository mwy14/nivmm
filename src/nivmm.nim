import kvm/vm

proc main() =
  let vm = newVm()
  # vm.loadCode(strToCode("Hello from the guest\n"))
  vm.loadKernel("/boot/vmlinuz-linux")
  vm.setupCpuId()
  vm.setupRegs()
  vm.run()
  vm.destroy()

main()
