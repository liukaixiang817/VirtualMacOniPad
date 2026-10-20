#!/usr/bin/env python3
"""Declared genuine HID type/class/generic-pattern Swift relative metadata.

Uses pinned Metadata.h/GenericContext.h layouts. Unknown trailing schemas are
rejected. Original function/default/PAC bytes are never substituted.
"""
from swift_relative_metadata import RelativeMetadata


class HIDTypeMetadata(RelativeMetadata):
    def bounds(self,at,size):
        _,s=self.section(at);assert at+size<=s['address']+s['size']

    def function(self,at,label,nullable=False):
        value=self.read(at,'<i')[0]
        if nullable and not value:return
        assert value and value&3==0, 'unsupported compact function indirection'
        _,destination=self.section(at+value);assert destination['flags']&0x80000000
        self.relative(at,label,nullable=nullable)

    def signature(self,at):
        self.bounds(at,12);f=self.read(at,'<I')[0];kind=f&31
        assert f&~0x9f==0 and kind in(0,1,2,3,4,31)
        self.relative(at+4,'typeGenericParameter')
        if kind==0:self.relative(at+8,'typeGenericProtocol',True)
        elif kind in(1,2,4):self.relative(at+8,'typeGenericType')
        elif kind==3:self.relative(at+8,'typeGenericConformance',True)

    def pattern(self,at):
        self.bounds(at,32)
        _,_,flags,_,_,classflags,ro,meta,metaro,prefix=self.read(at,'<iiIiiIHHHH')
        assert flags&~0x80000001==0 and classflags==2 and prefix==0
        self.schemas.append(dict(descriptor=at,kind='genericClassPattern',flags=flags,
                                 classFlags=classflags,classROOffset=ro,metaclassOffset=meta,metaclassROOffset=metaro))
        self.function(at,'patternInstantiationFunction')
        self.function(at+4,'patternCompletionFunction',True)
        self.function(at+12,'patternDestroyFunction')
        self.function(at+16,'patternIVarDestroyFunction',True)
        cursor=at+32
        for extra in range(int(bool(flags&1))+int(bool(flags&0x80000000))):
            self.bounds(cursor,8);word,offset,size=self.read(cursor,'<iHH');target=cursor+word
            assert target%8==0 and size>0
            self.bounds(target,size*8)
            if extra==0 and flags&1:assert max(ro,meta,metaro)<offset+size
            self.schemas.append(dict(descriptor=cursor,kind='genericClassPartialPattern',offsetWords=offset,sizeWords=size,target=target))
            self.relative(cursor,'patternPartialData');cursor+=8

    def types(self):
        for descriptor in self.entries('__swift5_types'):
            flags=self.read(descriptor,'<I')[0];kind=flags&31;specific=flags>>16;generic=bool(flags&0x80)
            assert kind in(16,17,18)and flags&0xff00==0
            allowed={16:{6,0x8000,0x8001,0x4001,0xc001},17:{0,0x10,0x11,0x12},18:{0,6,0x10}}
            assert specific in allowed[kind], 'unsupported type trailing flags'
            assert not generic or kind==16 and specific==0x8000
            base=44 if kind==16 else 28;self.bounds(descriptor,base)
            self.schemas.append(dict(descriptor=descriptor,kind='declaredType',typeKind=kind,flags=flags,generic=generic))
            self.relative(descriptor+4,'typeParent',True,nullable=True)
            self.relative(descriptor+8,'typeName')
            self.function(descriptor+12,'typeAccessFunction',True)
            self.relative(descriptor+16,'typeFields',nullable=True)
            if kind==16:self.relative(descriptor+20,'classSuperclassType',nullable=True)
            cursor=descriptor+base
            if generic:
                self.bounds(cursor,16);_,pattern,np,nr,nk,gf=self.read(cursor,'<iiHHHH')
                assert 0<np<=1024 and nr<=1024 and nk<=np+nr and gf==0
                self.relative(cursor,'typeInstantiationCache')
                self.relative(cursor+4,'typeInstantiationPattern');self.pattern(cursor+4+pattern)
                params=[self.read(cursor+16+i,'<B')[0]for i in range(np)]
                assert all(p in(0,0x80)for p in params)
                end=cursor+16+np;cursor=(end+3)&~3
                assert not any(self.raw[self.offset(end):self.offset(cursor)])
                for _ in range(nr):self.signature(cursor);cursor+=12
            else:
                initialization=specific&3
                if initialization==1:
                    self.bounds(cursor,12)
                    self.relative(cursor,'typeInitializationCache')
                    self.relative(cursor+4,'typeIncompleteMetadata')
                    self.function(cursor+8,'typeCompletionFunction',True);cursor+=12
                elif initialization==2:
                    self.bounds(cursor,4);self.function(cursor,'typeForeignCompletionFunction',True);cursor+=4
            if kind==16:
                if specific&0x8000:
                    self.bounds(cursor,8);offset,count=self.read(cursor,'<II');assert count<1024
                    self.schemas.append(dict(descriptor=cursor,kind='classVTable',offsetWords=offset,count=count));cursor+=8
                    for _ in range(count):
                        self.bounds(cursor,8);methodflags=self.read(cursor,'<I')[0]
                        # All this exact scope's methods are synchronous native
                        # entries. Async/coroutine data need separate schemas.
                        assert methodflags&~0xffff003f==0 and not methodflags&0x20
                        # TargetCompactFunctionPointer defaults Nullable=true
                        # (TargetLayout.h). Preserve genuine absent entries.
                        self.function(cursor+4,'typeClassVTableMethod',True);cursor+=8
                if specific&0x4000:
                    self.bounds(cursor,4);count=self.read(cursor,'<I')[0];assert count<1024
                    self.schemas.append(dict(descriptor=cursor,kind='classOverrideTable',count=count));cursor+=4
                    for _ in range(count):
                        self.bounds(cursor,12)
                        self.relative(cursor,'typeOverrideClass',True)
                        self.relative(cursor+4,'typeOverrideMethod',True)
                        self.function(cursor+8,'typeOverrideImplementation',True);cursor+=12
            self.schemas[-1]['typeTrailingEnd']=cursor
