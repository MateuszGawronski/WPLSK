#ifndef DEVICES_H
#define DEVICES_H

#include <net/if.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

class Devices
{
public:
    Devices();
    ~Devices();
    void Find_Devices();

public:
    char **device_all;
    int device_count;
};

#endif // DEVICES_H
