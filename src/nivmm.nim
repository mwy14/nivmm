import kvm/vm

proc main() =
  let vm = newVm()
  vm.loadCode([0xBA'u8, 0xF8, 0x03, 0xB0, 0x48, 0xEE, 0xF4])
  vm.setupRegs()
  vm.run()
  vm.destroy()

main()
