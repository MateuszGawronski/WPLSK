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
    void Find_Devices();    /* przeszukuje dostępne interfejsy sieciowe i dodaje do tablicy */

public:
    char **device_all;      /* przechowuje listę dostępnych interfejsów sieciowych */
    int device_count;       /* przechowuje liczbę dostępnych interfejsów sieciowych */
};

#endif // DEVICES_H
