; Owned implementation of the actual closed StaticCN generic method protocol.
; No raw cache method address, native CPU/VM call or runtime class alias.
%swift.opaque = type opaque
%swift.metadata_response = type { ptr, i64 }

declare swiftcc %swift.metadata_response @"$sSqMa"(i64, ptr)
declare i64 @llvm.ptrauth.blend(i64, i64)
declare i64 @llvm.ptrauth.auth(i64, i32 immarg, i64)
declare void @llvm.trap() noreturn nounwind
declare ptr @llvm.stacksave.p0()
declare void @llvm.stackrestore.p0(ptr)

; R? = nil uses R's enum single-payload witness exactly as original +112.
define swiftcc void @VM27StaticCNVerbatimNil(ptr noalias sret(%swift.opaque) %result, ptr %body, ptr %context, ptr %R, ptr swiftself %self, ptr noalias swifterror %error) #0 {
entry:
  %vwtSlot = getelementptr i8, ptr %R, i64 -8
  %vwtRaw = load i64, ptr %vwtSlot, align 8
  %vwtAddress = ptrtoint ptr %vwtSlot to i64
  %vwtDisc = call i64 @llvm.ptrauth.blend(i64 %vwtAddress, i64 11839)
  %vwtBits = call i64 @llvm.ptrauth.auth(i64 %vwtRaw, i32 2, i64 %vwtDisc)
  %vwt = inttoptr i64 %vwtBits to ptr
  %setSlot = getelementptr i8, ptr %vwt, i64 56
  %set = load ptr, ptr %setSlot, align 8
  %setAddress = ptrtoint ptr %setSlot to i64
  %setDisc = call i64 @llvm.ptrauth.blend(i64 %setAddress, i64 41169)
  call void %set(ptr %result, i32 1, i32 1, ptr %R) [ "ptrauth"(i32 0, i64 %setDisc) ]
  ret void
}

; The actual old428B and genuine416B +88 frames have the same Swift ABI.
; Optional<R> is a genuine runtime metadata result; dynamic scratch storage
; follows its actual VWT size, and payload ownership follows R's real witnesses.
define swiftcc void @VM27StaticCNWithUnsafeBufferOfObjects(ptr noalias sret(%swift.opaque) %result, ptr %body, ptr %context, ptr %R, ptr swiftself %self, ptr noalias swifterror %error) #0 {
entry:
  %response = call swiftcc %swift.metadata_response @"$sSqMa"(i64 0, ptr %R)
  %optional = extractvalue %swift.metadata_response %response, 0
  %optionalVWTSlot = getelementptr i8, ptr %optional, i64 -8
  %optionalVWTRaw = load i64, ptr %optionalVWTSlot, align 8
  %optionalVWTAddress = ptrtoint ptr %optionalVWTSlot to i64
  %optionalVWTDisc = call i64 @llvm.ptrauth.blend(i64 %optionalVWTAddress, i64 11839)
  %optionalVWTBits = call i64 @llvm.ptrauth.auth(i64 %optionalVWTRaw, i32 2, i64 %optionalVWTDisc)
  %optionalVWT = inttoptr i64 %optionalVWTBits to ptr
  %sizeSlot = getelementptr i8, ptr %optionalVWT, i64 64
  %size = load i64, ptr %sizeSlot, align 8
  %plus15 = add i64 %size, 15
  %alignedSize = and i64 %plus15, -16
  %saved = call ptr @llvm.stacksave.p0()
  %temporary = alloca i8, i64 %alignedSize, align 16
  %classRaw = load i64, ptr %self, align 8
  %selfAddress = ptrtoint ptr %self to i64
  %classDisc = call i64 @llvm.ptrauth.blend(i64 %selfAddress, i64 27361)
  %classBits = call i64 @llvm.ptrauth.auth(i64 %classRaw, i32 2, i64 %classDisc)
  %class = inttoptr i64 %classBits to ptr
  %bridgeSlot = getelementptr i8, ptr %class, i64 112
  %bridge = load ptr, ptr %bridgeSlot, align 8
  %bridgeAddress = ptrtoint ptr %bridgeSlot to i64
  %bridgeDisc = call i64 @llvm.ptrauth.blend(i64 %bridgeAddress, i64 46600)
  call swiftcc void %bridge(ptr sret(%swift.opaque) %temporary, ptr %body, ptr %context, ptr %R, ptr swiftself %self, ptr swifterror %error) [ "ptrauth"(i32 0, i64 %bridgeDisc) ]
  %errorValue = load ptr, ptr %error, align 8
  %failed = icmp ne ptr %errorValue, null
  br i1 %failed, label %finished, label %inspect
inspect:
  %rVWTSlot = getelementptr i8, ptr %R, i64 -8
  %rVWTRaw = load i64, ptr %rVWTSlot, align 8
  %rVWTAddress = ptrtoint ptr %rVWTSlot to i64
  %rVWTDisc = call i64 @llvm.ptrauth.blend(i64 %rVWTAddress, i64 11839)
  %rVWTBits = call i64 @llvm.ptrauth.auth(i64 %rVWTRaw, i32 2, i64 %rVWTDisc)
  %rVWT = inttoptr i64 %rVWTBits to ptr
  %tagSlot = getelementptr i8, ptr %rVWT, i64 48
  %tagFunction = load ptr, ptr %tagSlot, align 8
  %tagAddress = ptrtoint ptr %tagSlot to i64
  %tagDisc = call i64 @llvm.ptrauth.blend(i64 %tagAddress, i64 24816)
  %tag = call i32 %tagFunction(ptr %temporary, i32 1, ptr %R) [ "ptrauth"(i32 0, i64 %tagDisc) ]
  %none = icmp eq i32 %tag, 1
  br i1 %none, label %invalidNone, label %take
take:
  %takeSlot = getelementptr i8, ptr %rVWT, i64 32
  %takeFunction = load ptr, ptr %takeSlot, align 8
  %takeAddress = ptrtoint ptr %takeSlot to i64
  %takeDisc = call i64 @llvm.ptrauth.blend(i64 %takeAddress, i64 18648)
  %ignored = call ptr %takeFunction(ptr %result, ptr %temporary, ptr %R) [ "ptrauth"(i32 0, i64 %takeDisc) ]
  br label %finished
finished:
  call void @llvm.stackrestore.p0(ptr %saved)
  ret void
invalidNone:
  %destroySlot = getelementptr i8, ptr %optionalVWT, i64 8
  %destroy = load ptr, ptr %destroySlot, align 8
  %destroyAddress = ptrtoint ptr %destroySlot to i64
  %destroyDisc = call i64 @llvm.ptrauth.blend(i64 %destroyAddress, i64 1272)
  call void %destroy(ptr %temporary, ptr %optional) [ "ptrauth"(i32 0, i64 %destroyDisc) ]
  call void @llvm.trap()
  unreachable
}

define swiftcc i1 @VM27StaticCNCanStoreElements(ptr %dynamicType, ptr swiftself %self) #0 {
  ret i1 false
}

define swiftcc ptr @VM27StaticCNDoNotCallMe(ptr swiftself %self) noreturn #0 {
  call void @llvm.trap()
  unreachable
}

define swiftcc void @VM27StaticCNDeallocator(ptr swiftself %self) noreturn #0 {
  call void @llvm.trap()
  unreachable
}

attributes #0 = { "frame-pointer"="non-leaf" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-returns" }
!llvm.module.flags = !{!0}
!0 = !{i32 6, !"ptrauth.abi-version", !1}
!1 = !{!2}
!2 = !{i32 0, i1 false}
