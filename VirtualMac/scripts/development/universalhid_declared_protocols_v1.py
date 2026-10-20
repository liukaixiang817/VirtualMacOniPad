#!/usr/bin/env python3
"""Declared HID protocol and associated-type metadata, using pinned Swift ABI.

Only __swift5_protos entries and __swift5_assocty record boundaries are used.
Unknown generic/special protocol schemas reject; no arbitrary const scanning.
"""
from swift_relative_metadata import RelativeMetadata


class HIDDeclaredProtocols(RelativeMetadata):
    def requirement(self,at,external):
        flags=self.read(at,'<I')[0];kind=flags&31
        assert not flags&~0x9f and kind in (0,1,2,3,4,31), 'unsupported signature requirement'
        self.relative(at+4,'ownProtocolSignatureParameter',external=external)
        if kind==0:self.relative(at+8,'ownProtocolSignatureProtocol',True,external=external)
        elif kind in (1,2,4):self.relative(at+8,'ownProtocolSignatureType',external=external)
        elif kind==3:self.relative(at+8,'ownProtocolSignatureConformance',True,external=external)

    def protocols(self,external=None):
        for descriptor in self.entries('__swift5_protos'):
            flags,_,_,signatures,requirements,_=self.read(descriptor,'<IiiIIi')
            # Ordinary non-generic protocols only. No COM identity or inverted
            # protocol trailing layout is silently treated as a requirement.
            assert flags&31==3 and not flags&0x80 and not flags&0xfc00
            assert (flags>>16)&~3==0 and signatures<1024 and requirements<1024
            _,section=self.section(descriptor)
            end=descriptor+24+signatures*12+requirements*8
            assert end<=section['address']+section['size'], 'protocol trailing data crosses section'
            self.schemas.append(dict(descriptor=descriptor,kind='declaredOwnProtocol',flags=flags,
                                     signatureRequirements=signatures,protocolRequirements=requirements,end=end))
            self.relative(descriptor+4,'ownProtocolParent',True,nullable=True,external=external)
            self.relative(descriptor+8,'ownProtocolName',external=external)
            self.relative(descriptor+20,'ownProtocolAssociatedTypeNames',nullable=True,external=external)
            at=descriptor+24
            for _ in range(signatures):self.requirement(at,external);at+=12
            for index in range(requirements):
                rf,word=self.read(at,'<Ii');kind=rf&15
                assert not rf&~0xffff003f and kind<=8, 'unsupported protocol requirement flags'
                self.schemas.append(dict(descriptor=at,kind='ownProtocolRequirement',flags=rf,
                                         requirementKind=kind,index=index,defaultImplementation=bool(word)))
                if word:
                    # Compact native function defaults in these originals are
                    # direct, aligned references to the same declared text.
                    # Async/coroutine data and associated type/conformance
                    # defaults use the explicit RelativeDirectPointer union.
                    native=kind in (1,2,3,4,5,6)and not rf&0x20
                    target=at+4+word
                    _,destination=self.section(target)
                    if native:assert word&3==0 and destination['name']=='__text'
                    self.relative(at+4,'ownProtocolDefaultFunction'if native else'ownProtocolDefaultData',external=external)
                at+=8

    def associated_types(self,external=None):
        sections=[s for g in self.old for s in g['sections']if s['name']=='__swift5_assocty']
        if not sections:return
        assert len(sections)==1;section=sections[0];at=section['address'];end=at+section['size']
        while at<end:
            assert at+16<=end
            _,_,count,size=self.read(at,'<iiII')
            assert size==8 and count<1024 and at+16+count*size<=end
            self.schemas.append(dict(descriptor=at,kind='associatedTypeDescriptor',count=count,recordBytes=size))
            self.relative(at,'associatedConformingType',external=external)
            self.relative(at+4,'associatedProtocolType',external=external)
            for index in range(count):
                record=at+16+index*size
                self.relative(record,'associatedTypeName',external=external)
                self.relative(record+4,'associatedSubstitutedType',external=external)
            at+=16+count*size
        assert at==end
