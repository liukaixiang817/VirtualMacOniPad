; Ordinary distinct own heap class. No original class, raw cached method or CPU.
declare void @VM27OldN2OwnDestroyed(ptr)
declare void @swift_deallocClassInstance(ptr, i64, i64)
define swiftcc void @VM27StaticCNModelDeallocator(ptr swiftself %self) #0 {
  call void @VM27OldN2OwnDestroyed(ptr %self)
  call void @swift_deallocClassInstance(ptr %self, i64 32, i64 7)
  ret void
}
attributes #0 = { "frame-pointer"="non-leaf" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-returns" }
!llvm.module.flags = !{!0}
!0 = !{i32 6, !"ptrauth.abi-version", !1}
!1 = !{!2}
!2 = !{i32 0, i1 false}
