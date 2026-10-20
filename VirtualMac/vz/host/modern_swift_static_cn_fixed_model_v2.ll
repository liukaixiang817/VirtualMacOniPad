; Ordinary Mac fixture only. The unsigned iOS object never links this module.
; A distinct own class can be heap-owned for retain/destruction testing;
; this wrapper observes destruction then calls the corrected product CfD.
declare void @VM27FixtureOwnDestroyed(ptr)
declare swiftcc void @VM27StaticCNDeallocator(ptr swiftself)
%swift.opaque = type opaque
declare swiftcc void @VM27FixtureReturnOptional(ptr sret(%swift.opaque), ptr, ptr swiftself, ptr swifterror)

; This bridge belongs only to a distinct real Mac control class. Swift emits
; the actual generic Optional<R> value and native Swift error ownership.
define swiftcc void @VM27StaticCNModelBridgeControl(ptr sret(%swift.opaque) %result, ptr %body, ptr %context, ptr %R, ptr swiftself %self, ptr swifterror %error) #0 {
  call swiftcc void @VM27FixtureReturnOptional(ptr sret(%swift.opaque) %result, ptr %R, ptr swiftself null, ptr swifterror %error)
  ret void
}

define swiftcc void @VM27StaticCNModelDeallocator(ptr swiftself %self) #0 {
  call void @VM27FixtureOwnDestroyed(ptr %self)
  call swiftcc void @VM27StaticCNDeallocator(ptr swiftself %self)
  ret void
}
attributes #0 = { "frame-pointer"="non-leaf" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-returns" }
!llvm.module.flags = !{!0}
!0 = !{i32 6, !"ptrauth.abi-version", !1}
!1 = !{!2}
!2 = !{i32 0, i1 false}
