# Pure native IPA-field conversion, schema1

`VZFrameworkComputeMaxIPAFromNativeV1` is an input adapter. It neither invokes a
kernel operation nor exports the original `hv_vm_config_get_max_ipa_size` API.
A future acquisition caller must independently validate its own exact native
operation0, pinned iPadOS16.1.1 profile, original352-byte zero input, returned
status, canaries, buffer lifetime and raw evidence. The function cannot
authenticate those caller-supplied provenance fields.

The original13 native query buffer begins at RVA`0x1c060` and ends before the
dispatch sentinel at`0x1c1c0`. The maximum-IPA consumer reads packed LE u64 at
global RVAs`0x1c1a9` and`0x1c1b1`: wire offsets`0x149` and`0x151`.
Original27 performs the same unsigned minimum and high32 rejection using its
own capability-object accessors at offsets`0x1a1` and`0x1a9`. These are distinct
layouts; the adapter never gives the original27 framework a raw old-layout
pointer or fabricates a modern capability object.

Schema, profile, operation, pointer/capacity and overlap failures return
`HV_BAD_ARGUMENT`. An incomplete query returns the original generic
`HV_ERROR`(`0xfae94001`). A completed nonzero native status propagates exactly
without reading the packed fields. Either nonzero high32 also returns
`HV_ERROR`. Only after all gates pass is the unsigned minimum written to the
four-byte output. Every failure preserves that output and the wire buffer.

The saved actual operation0 run records only the first328 bytes and explicitly
does not consume the tail. It therefore supplies no actual maximum-IPA value.
Model inputs and local conversion calls must not be described as iPad
capability measurements. Zero input alone does not prove a query occurred.
The public header's36-bit example is not used as a maximum or fallback.
