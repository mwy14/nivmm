import kvm/vm

proc main() =
  let vm = newVm()
  vm.loadCode(strToCode("Hello from the guest\n"))
  vm.setupRegs()
  vm.loadKernel("/boot/vmlinuz-linux")
  vm.run()
  vm.destroy()

main()
