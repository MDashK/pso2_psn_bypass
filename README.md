# PSO2 PSN Bypass
A PSVita plugin for usage on PSO2 to bypass the need to connect to PSN servers.

# Usage

1. Place "pso2_psn_bypass.suprx" file in "ur0:tai".
2. Change "config.ini" to reflect the following:
```
*PCSG00141
ur0:tai/pso2_psn_bypass.suprx
```
4. Reboot
5. Open PSO2 and the game should jump to the server list without touching PSN servers.


# How to compile

1. Install VitaSDK
2. In the project folder, where .c file is:
```
cmake .. -DCMAKE_TOOLCHAIN_FILE="$VITASDK/share/vita.toolchain.cmake"
```
3. Then
```
make
```
4. The .suprx file should now be present in the build folder.

