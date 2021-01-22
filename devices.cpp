#include "devices.h"

Devices::Devices()
{

}

Devices::~Devices()
{

}

void Devices::Find_Devices()
{

    struct if_nameindex *if_ni, *i;
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        device_all = new char *[1];
        strcpy(device_all[0], "error");
        return;
    }
    device_count = sizeof(if_ni) / sizeof(if_ni[0]);
    device_all = new char *[device_count];
    int device_index = 0;
    for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
        device_all[device_index] = i->if_name;
        device_index = device_index + 1;
    }
    device_count = device_index;
}
