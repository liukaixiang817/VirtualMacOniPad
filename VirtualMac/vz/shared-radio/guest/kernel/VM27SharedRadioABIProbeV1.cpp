// Development preflight only: publish exact live class-size checks. No radio,
// PCI, network-interface or user-client operations are performed by this kext.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/version.h>

class VM27SharedRadioABIProbeV1 : public IOService {
    OSDeclareDefaultStructors(VM27SharedRadioABIProbeV1)
public:
    bool start(IOService *provider) override;
};
OSDefineMetaClassAndStructors(VM27SharedRadioABIProbeV1, IOService)

static bool contains(const char *text, const char *part) {
    size_t size = strlen(part);
    if (!size) return false;
    for (; *text; ++text) if (!strncmp(text, part, size)) return true;
    return false;
}

bool VM27SharedRadioABIProbeV1::start(IOService *provider) {
    if (!IOService::start(provider)) return false;
    OSString *wantedKernel = OSDynamicCast(OSString, getProperty("ExpectedXNU"));
    OSDictionary *wantedSizes = OSDynamicCast(OSDictionary, getProperty("ExpectedClassSizes"));
    if (!wantedKernel || !wantedSizes || !contains(version, wantedKernel->getCStringNoCopy())) return false;
    OSCollectionIterator *iterator = OSCollectionIterator::withCollection(wantedSizes);
    if (!iterator) return false;
    OSDictionary *actual = OSDictionary::withCapacity(wantedSizes->getCount());
    bool match = actual != nullptr;
    while (OSSymbol *name = OSDynamicCast(OSSymbol, iterator->getNextObject())) {
        const OSMetaClass *meta = OSMetaClass::getMetaClassWithName(name);
        OSNumber *expected = OSDynamicCast(OSNumber, wantedSizes->getObject(name));
        unsigned size = meta ? meta->getClassSize() : 0;
        if (!expected || !size || size != expected->unsigned32BitValue()) match = false;
        if (actual) {
            OSNumber *number = OSNumber::withNumber(size, 32);
            if (number) { actual->setObject(name, number); number->release(); }
            else match = false;
        }
    }
    iterator->release();
    if (actual) { setProperty("ActualClassSizes", actual); actual->release(); }
    setProperty("NativeABIReady", match);
    setProperty("RadioHardwareOpened", false);
    setProperty("NativeWiFiInterfaceCreated", false);
    IOLog("VM27SharedRadioABIProbeV1: live ARM64e class sizes match=%d\n", match);
    registerService();
    return true;
}
