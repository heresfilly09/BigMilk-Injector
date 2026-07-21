Microsoft (R) COFF/PE Dumper Version 14.44.35222.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file C:\Users\user\Downloads\BigMilk-Injector\target\release\build\bigmilk-injector-36a961e92d87fd7e\out\96203b7dd65a9ffd-shellcode.o

File Type: COFF OBJECT

?poly_delay@@YAXXZ (void __cdecl poly_delay(void)):
  0000000000000000: 48 83 EC 38        sub         rsp,38h
  0000000000000004: C7 04 24 3F 03 F7  mov         dword ptr [rsp],78F7033Fh
                    78
  000000000000000B: C7 44 24 04 45 32  mov         dword ptr [rsp+4],70E83245h
                    E8 70
  0000000000000013: C7 44 24 08 B9 35  mov         dword ptr [rsp+8],0E85835B9h
                    58 E8
  000000000000001B: C7 44 24 0C B5 10  mov         dword ptr [rsp+0Ch],311D10B5h
                    1D 31
  0000000000000023: 48 C7 44 24 18 00  mov         qword ptr [rsp+18h],0
                    00 00 00
  000000000000002C: 48 C7 44 24 10 00  mov         qword ptr [rsp+10h],0
                    00 00 00
  0000000000000035: EB 0D              jmp         0000000000000044
  0000000000000037: 48 8B 44 24 10     mov         rax,qword ptr [rsp+10h]
  000000000000003C: 48 FF C0           inc         rax
  000000000000003F: 48 89 44 24 10     mov         qword ptr [rsp+10h],rax
  0000000000000044: 48 83 7C 24 10 0C  cmp         qword ptr [rsp+10h],0Ch
  000000000000004A: 73 22              jae         000000000000006E
  000000000000004C: B8 D4 A7 85 DB     mov         eax,0DB85A7D4h
  0000000000000051: 48 8B 4C 24 10     mov         rcx,qword ptr [rsp+10h]
  0000000000000056: 48 33 C8           xor         rcx,rax
  0000000000000059: 48 8B C1           mov         rax,rcx
  000000000000005C: 48 8B 4C 24 18     mov         rcx,qword ptr [rsp+18h]
  0000000000000061: 48 33 C8           xor         rcx,rax
  0000000000000064: 48 8B C1           mov         rax,rcx
  0000000000000067: 48 89 44 24 18     mov         qword ptr [rsp+18h],rax
  000000000000006C: EB C9              jmp         0000000000000037
  000000000000006E: 48 8B 44 24 18     mov         rax,qword ptr [rsp+18h]
  0000000000000073: 48 89 44 24 20     mov         qword ptr [rsp+20h],rax
  0000000000000078: 48 83 C4 38        add         rsp,38h
  000000000000007C: C3                 ret

?poly_mutate@@YAXXZ (void __cdecl poly_mutate(void)):
  0000000000000000: 48 83 EC 28        sub         rsp,28h
  0000000000000004: C7 04 24 3B 8C D2  mov         dword ptr [rsp],0BED28C3Bh
                    BE
  000000000000000B: 8B 04 24           mov         eax,dword ptr [rsp]
  000000000000000E: 05 AC 45 86 4A     add         eax,4A8645ACh
  0000000000000013: 89 04 24           mov         dword ptr [rsp],eax
  0000000000000016: 8B 04 24           mov         eax,dword ptr [rsp]
  0000000000000019: 89 44 24 10        mov         dword ptr [rsp+10h],eax
  000000000000001D: C7 44 24 04 C6 BC  mov         dword ptr [rsp+4],0EDE6BCC6h
                    E6 ED
  0000000000000025: 8B 44 24 04        mov         eax,dword ptr [rsp+4]
  0000000000000029: 0D FF 86 21 58     or          eax,582186FFh
  000000000000002E: 89 44 24 04        mov         dword ptr [rsp+4],eax
  0000000000000032: 8B 44 24 04        mov         eax,dword ptr [rsp+4]
  0000000000000036: 89 44 24 14        mov         dword ptr [rsp+14h],eax
  000000000000003A: C7 44 24 08 14 6F  mov         dword ptr [rsp+8],0B2996F14h
                    99 B2
  0000000000000042: 8B 44 24 08        mov         eax,dword ptr [rsp+8]
  0000000000000046: 0D 7B C8 A3 75     or          eax,75A3C87Bh
  000000000000004B: 89 44 24 08        mov         dword ptr [rsp+8],eax
  000000000000004F: 8B 44 24 08        mov         eax,dword ptr [rsp+8]
  0000000000000053: 89 44 24 18        mov         dword ptr [rsp+18h],eax
  0000000000000057: C7 44 24 0C EC FE  mov         dword ptr [rsp+0Ch],7753FEECh
                    53 77
  000000000000005F: 8B 44 24 0C        mov         eax,dword ptr [rsp+0Ch]
  0000000000000063: 25 95 BC B8 72     and         eax,72B8BC95h
  0000000000000068: 89 44 24 0C        mov         dword ptr [rsp+0Ch],eax
  000000000000006C: 8B 44 24 0C        mov         eax,dword ptr [rsp+0Ch]
  0000000000000070: 89 44 24 1C        mov         dword ptr [rsp+1Ch],eax
  0000000000000074: 48 83 C4 28        add         rsp,28h
  0000000000000078: C3                 ret

Shellcode:
  0000000000000000: 48 89 4C 24 08     mov         qword ptr [rsp+8],rcx
  0000000000000005: 48 81 EC 08 01 00  sub         rsp,108h
                    00
  000000000000000C: 48 83 BC 24 10 01  cmp         qword ptr [rsp+110h],0
                    00 00 00
  0000000000000015: 75 15              jne         000000000000002C
  0000000000000017: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  000000000000001F: 48 C7 40 20 40 40  mov         qword ptr [rax+20h],404040h
                    40 00
  0000000000000027: E9 A2 07 00 00     jmp         00000000000007CE
  000000000000002C: E8 00 00 00 00     call        ?poly_delay@@YAXXZ
  0000000000000031: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000039: 48 8B 40 18        mov         rax,qword ptr [rax+18h]
  000000000000003D: 48 89 44 24 30     mov         qword ptr [rsp+30h],rax
  0000000000000042: 48 8B 44 24 30     mov         rax,qword ptr [rsp+30h]
  0000000000000047: 48 63 40 3C        movsxd      rax,dword ptr [rax+3Ch]
  000000000000004B: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  0000000000000050: 48 8D 44 01 18     lea         rax,[rcx+rax+18h]
  0000000000000055: 48 89 44 24 40     mov         qword ptr [rsp+40h],rax
  000000000000005A: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000062: 48 8B 00           mov         rax,qword ptr [rax]
  0000000000000065: 48 89 84 24 E8 00  mov         qword ptr [rsp+0E8h],rax
                    00 00
  000000000000006D: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000075: 48 8B 40 08        mov         rax,qword ptr [rax+8]
  0000000000000079: 48 89 84 24 B8 00  mov         qword ptr [rsp+0B8h],rax
                    00 00
  0000000000000081: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000089: 48 8B 40 10        mov         rax,qword ptr [rax+10h]
  000000000000008D: 48 89 84 24 C8 00  mov         qword ptr [rsp+0C8h],rax
                    00 00
  0000000000000095: 48 8B 44 24 40     mov         rax,qword ptr [rsp+40h]
  000000000000009A: 8B 40 10           mov         eax,dword ptr [rax+10h]
  000000000000009D: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000000A2: 48 03 C8           add         rcx,rax
  00000000000000A5: 48 8B C1           mov         rax,rcx
  00000000000000A8: 48 89 84 24 F8 00  mov         qword ptr [rsp+0F8h],rax
                    00 00
  00000000000000B0: C7 84 24 88 00 00  mov         dword ptr [rsp+88h],0C1C7F791h
                    00 91 F7 C7 C1
  00000000000000BB: 8B 84 24 88 00 00  mov         eax,dword ptr [rsp+88h]
                    00
  00000000000000C2: 89 84 24 D0 00 00  mov         dword ptr [rsp+0D0h],eax
                    00
  00000000000000C9: 48 8B 44 24 40     mov         rax,qword ptr [rsp+40h]
  00000000000000CE: 48 8B 40 18        mov         rax,qword ptr [rax+18h]
  00000000000000D2: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000000D7: 48 2B C8           sub         rcx,rax
  00000000000000DA: 48 8B C1           mov         rax,rcx
  00000000000000DD: 48 89 84 24 98 00  mov         qword ptr [rsp+98h],rax
                    00 00
  00000000000000E5: 48 83 BC 24 98 00  cmp         qword ptr [rsp+98h],0
                    00 00 00
  00000000000000EE: 0F 84 69 01 00 00  je          000000000000025D
  00000000000000F4: B8 08 00 00 00     mov         eax,8
  00000000000000F9: 48 6B C0 05        imul        rax,rax,5
  00000000000000FD: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  0000000000000102: 83 7C 01 74 00     cmp         dword ptr [rcx+rax+74h],0
  0000000000000107: 0F 84 50 01 00 00  je          000000000000025D
  000000000000010D: B8 08 00 00 00     mov         eax,8
  0000000000000112: 48 6B C0 05        imul        rax,rax,5
  0000000000000116: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  000000000000011B: 8B 44 01 70        mov         eax,dword ptr [rcx+rax+70h]
  000000000000011F: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  0000000000000124: 48 03 C8           add         rcx,rax
  0000000000000127: 48 8B C1           mov         rax,rcx
  000000000000012A: 48 89 44 24 48     mov         qword ptr [rsp+48h],rax
  000000000000012F: B8 08 00 00 00     mov         eax,8
  0000000000000134: 48 6B C0 05        imul        rax,rax,5
  0000000000000138: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  000000000000013D: 8B 44 01 74        mov         eax,dword ptr [rcx+rax+74h]
  0000000000000141: 48 8B 4C 24 48     mov         rcx,qword ptr [rsp+48h]
  0000000000000146: 48 03 C8           add         rcx,rax
  0000000000000149: 48 8B C1           mov         rax,rcx
  000000000000014C: 48 89 84 24 D8 00  mov         qword ptr [rsp+0D8h],rax
                    00 00
  0000000000000154: 48 8B 84 24 D8 00  mov         rax,qword ptr [rsp+0D8h]
                    00 00
  000000000000015C: 48 39 44 24 48     cmp         qword ptr [rsp+48h],rax
  0000000000000161: 0F 83 F6 00 00 00  jae         000000000000025D
  0000000000000167: 48 8B 44 24 48     mov         rax,qword ptr [rsp+48h]
  000000000000016C: 83 78 04 00        cmp         dword ptr [rax+4],0
  0000000000000170: 0F 84 E7 00 00 00  je          000000000000025D
  0000000000000176: 48 8B 44 24 48     mov         rax,qword ptr [rsp+48h]
  000000000000017B: 8B 40 04           mov         eax,dword ptr [rax+4]
  000000000000017E: 48 83 E8 08        sub         rax,8
  0000000000000182: 33 D2              xor         edx,edx
  0000000000000184: B9 02 00 00 00     mov         ecx,2
  0000000000000189: 48 F7 F1           div         rax,rcx
  000000000000018C: 89 84 24 8C 00 00  mov         dword ptr [rsp+8Ch],eax
                    00
  0000000000000193: 48 8B 44 24 48     mov         rax,qword ptr [rsp+48h]
  0000000000000198: 48 83 C0 08        add         rax,8
  000000000000019C: 48 89 84 24 80 00  mov         qword ptr [rsp+80h],rax
                    00 00
  00000000000001A4: C7 44 24 50 00 00  mov         dword ptr [rsp+50h],0
                    00 00
  00000000000001AC: EB 1E              jmp         00000000000001CC
  00000000000001AE: 8B 44 24 50        mov         eax,dword ptr [rsp+50h]
  00000000000001B2: FF C0              inc         eax
  00000000000001B4: 89 44 24 50        mov         dword ptr [rsp+50h],eax
  00000000000001B8: 48 8B 84 24 80 00  mov         rax,qword ptr [rsp+80h]
                    00 00
  00000000000001C0: 48 83 C0 02        add         rax,2
  00000000000001C4: 48 89 84 24 80 00  mov         qword ptr [rsp+80h],rax
                    00 00
  00000000000001CC: 8B 84 24 8C 00 00  mov         eax,dword ptr [rsp+8Ch]
                    00
  00000000000001D3: 39 44 24 50        cmp         dword ptr [rsp+50h],eax
  00000000000001D7: 74 67              je          0000000000000240
  00000000000001D9: 48 8B 84 24 80 00  mov         rax,qword ptr [rsp+80h]
                    00 00
  00000000000001E1: 0F B7 00           movzx       eax,word ptr [rax]
  00000000000001E4: C1 F8 0C           sar         eax,0Ch
  00000000000001E7: 83 F8 0A           cmp         eax,0Ah
  00000000000001EA: 75 4F              jne         000000000000023B
  00000000000001EC: 48 8B 44 24 48     mov         rax,qword ptr [rsp+48h]
  00000000000001F1: 8B 00              mov         eax,dword ptr [rax]
  00000000000001F3: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000001F8: 48 03 C8           add         rcx,rax
  00000000000001FB: 48 8B C1           mov         rax,rcx
  00000000000001FE: 48 8B 8C 24 80 00  mov         rcx,qword ptr [rsp+80h]
                    00 00
  0000000000000206: 0F B7 09           movzx       ecx,word ptr [rcx]
  0000000000000209: 81 E1 FF 0F 00 00  and         ecx,0FFFh
  000000000000020F: 48 63 C9           movsxd      rcx,ecx
  0000000000000212: 48 03 C1           add         rax,rcx
  0000000000000215: 48 89 84 24 A0 00  mov         qword ptr [rsp+0A0h],rax
                    00 00
  000000000000021D: 48 8B 84 24 A0 00  mov         rax,qword ptr [rsp+0A0h]
                    00 00
  0000000000000225: 48 8B 00           mov         rax,qword ptr [rax]
  0000000000000228: 48 03 84 24 98 00  add         rax,qword ptr [rsp+98h]
                    00 00
  0000000000000230: 48 8B 8C 24 A0 00  mov         rcx,qword ptr [rsp+0A0h]
                    00 00
  0000000000000238: 48 89 01           mov         qword ptr [rcx],rax
  000000000000023B: E9 6E FF FF FF     jmp         00000000000001AE
  0000000000000240: 48 8B 44 24 48     mov         rax,qword ptr [rsp+48h]
  0000000000000245: 8B 40 04           mov         eax,dword ptr [rax+4]
  0000000000000248: 48 8B 4C 24 48     mov         rcx,qword ptr [rsp+48h]
  000000000000024D: 48 03 C8           add         rcx,rax
  0000000000000250: 48 8B C1           mov         rax,rcx
  0000000000000253: 48 89 44 24 48     mov         qword ptr [rsp+48h],rax
  0000000000000258: E9 F7 FE FF FF     jmp         0000000000000154
  000000000000025D: E8 00 00 00 00     call        ?poly_delay@@YAXXZ
  0000000000000262: E8 00 00 00 00     call        ?poly_mutate@@YAXXZ
  0000000000000267: 90                 nop
  0000000000000268: B8 08 00 00 00     mov         eax,8
  000000000000026D: 48 6B C0 01        imul        rax,rax,1
  0000000000000271: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  0000000000000276: 83 7C 01 74 00     cmp         dword ptr [rcx+rax+74h],0
  000000000000027B: 0F 84 B9 03 00 00  je          000000000000063A
  0000000000000281: B8 08 00 00 00     mov         eax,8
  0000000000000286: 48 6B C0 01        imul        rax,rax,1
  000000000000028A: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  000000000000028F: 8B 44 01 70        mov         eax,dword ptr [rcx+rax+70h]
  0000000000000293: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  0000000000000298: 48 03 C8           add         rcx,rax
  000000000000029B: 48 8B C1           mov         rax,rcx
  000000000000029E: 48 89 44 24 60     mov         qword ptr [rsp+60h],rax
  00000000000002A3: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  00000000000002A8: 83 78 0C 00        cmp         dword ptr [rax+0Ch],0
  00000000000002AC: 0F 84 88 03 00 00  je          000000000000063A
  00000000000002B2: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  00000000000002B7: 8B 40 0C           mov         eax,dword ptr [rax+0Ch]
  00000000000002BA: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000002BF: 48 03 C8           add         rcx,rax
  00000000000002C2: 48 8B C1           mov         rax,rcx
  00000000000002C5: 48 89 84 24 E0 00  mov         qword ptr [rsp+0E0h],rax
                    00 00
  00000000000002CD: 48 8B 8C 24 E0 00  mov         rcx,qword ptr [rsp+0E0h]
                    00 00
  00000000000002D5: FF 94 24 E8 00 00  call        qword ptr [rsp+0E8h]
                    00
  00000000000002DC: 48 89 84 24 B0 00  mov         qword ptr [rsp+0B0h],rax
                    00 00
  00000000000002E4: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  00000000000002E9: 8B 00              mov         eax,dword ptr [rax]
  00000000000002EB: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000002F0: 48 03 C8           add         rcx,rax
  00000000000002F3: 48 8B C1           mov         rax,rcx
  00000000000002F6: 48 89 44 24 58     mov         qword ptr [rsp+58h],rax
  00000000000002FB: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  0000000000000300: 8B 40 10           mov         eax,dword ptr [rax+10h]
  0000000000000303: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  0000000000000308: 48 03 C8           add         rcx,rax
  000000000000030B: 48 8B C1           mov         rax,rcx
  000000000000030E: 48 89 44 24 68     mov         qword ptr [rsp+68h],rax
  0000000000000313: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  0000000000000318: 83 38 00           cmp         dword ptr [rax],0
  000000000000031B: 75 0A              jne         0000000000000327
  000000000000031D: 48 8B 44 24 68     mov         rax,qword ptr [rsp+68h]
  0000000000000322: 48 89 44 24 58     mov         qword ptr [rsp+58h],rax
  0000000000000327: EB 1C              jmp         0000000000000345
  0000000000000329: 48 8B 44 24 58     mov         rax,qword ptr [rsp+58h]
  000000000000032E: 48 83 C0 08        add         rax,8
  0000000000000332: 48 89 44 24 58     mov         qword ptr [rsp+58h],rax
  0000000000000337: 48 8B 44 24 68     mov         rax,qword ptr [rsp+68h]
  000000000000033C: 48 83 C0 08        add         rax,8
  0000000000000340: 48 89 44 24 68     mov         qword ptr [rsp+68h],rax
  0000000000000345: 48 8B 44 24 58     mov         rax,qword ptr [rsp+58h]
  000000000000034A: 48 83 38 00        cmp         qword ptr [rax],0
  000000000000034E: 0F 84 D3 02 00 00  je          0000000000000627
  0000000000000354: 48 8B 44 24 58     mov         rax,qword ptr [rsp+58h]
  0000000000000359: 48 B9 00 00 00 00  mov         rcx,8000000000000000h
                    00 00 00 80
  0000000000000363: 48 8B 00           mov         rax,qword ptr [rax]
  0000000000000366: 48 23 C1           and         rax,rcx
  0000000000000369: 48 85 C0           test        rax,rax
  000000000000036C: 74 2D              je          000000000000039B
  000000000000036E: 48 8B 44 24 58     mov         rax,qword ptr [rsp+58h]
  0000000000000373: 48 8B 00           mov         rax,qword ptr [rax]
  0000000000000376: 48 25 FF FF 00 00  and         rax,0FFFFh
  000000000000037C: 48 8B D0           mov         rdx,rax
  000000000000037F: 48 8B 8C 24 B0 00  mov         rcx,qword ptr [rsp+0B0h]
                    00 00
  0000000000000387: FF 94 24 B8 00 00  call        qword ptr [rsp+0B8h]
                    00
  000000000000038E: 48 8B 4C 24 68     mov         rcx,qword ptr [rsp+68h]
  0000000000000393: 48 89 01           mov         qword ptr [rcx],rax
  0000000000000396: E9 87 02 00 00     jmp         0000000000000622
  000000000000039B: 48 8B 44 24 58     mov         rax,qword ptr [rsp+58h]
  00000000000003A0: 48 8B 00           mov         rax,qword ptr [rax]
  00000000000003A3: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000003A8: 48 03 C8           add         rcx,rax
  00000000000003AB: 48 8B C1           mov         rax,rcx
  00000000000003AE: 48 89 84 24 A8 00  mov         qword ptr [rsp+0A8h],rax
                    00 00
  00000000000003B6: 48 8B 84 24 A8 00  mov         rax,qword ptr [rsp+0A8h]
                    00 00
  00000000000003BE: 48 83 C0 02        add         rax,2
  00000000000003C2: 48 89 44 24 28     mov         qword ptr [rsp+28h],rax
  00000000000003C7: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  00000000000003CF: 48 83 78 40 00     cmp         qword ptr [rax+40h],0
  00000000000003D4: 0F 84 F2 01 00 00  je          00000000000005CC
  00000000000003DA: B8 01 00 00 00     mov         eax,1
  00000000000003DF: 48 6B C0 00        imul        rax,rax,0
  00000000000003E3: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000003E8: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000003EC: 83 F8 5F           cmp         eax,5Fh
  00000000000003EF: 0F 85 D7 01 00 00  jne         00000000000005CC
  00000000000003F5: B8 01 00 00 00     mov         eax,1
  00000000000003FA: 48 6B C0 01        imul        rax,rax,1
  00000000000003FE: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000403: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000407: 83 F8 43           cmp         eax,43h
  000000000000040A: 0F 85 BC 01 00 00  jne         00000000000005CC
  0000000000000410: B8 01 00 00 00     mov         eax,1
  0000000000000415: 48 6B C0 02        imul        rax,rax,2
  0000000000000419: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000041E: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000422: 83 F8 78           cmp         eax,78h
  0000000000000425: 0F 85 A1 01 00 00  jne         00000000000005CC
  000000000000042B: B8 01 00 00 00     mov         eax,1
  0000000000000430: 48 6B C0 03        imul        rax,rax,3
  0000000000000434: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000439: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  000000000000043D: 83 F8 78           cmp         eax,78h
  0000000000000440: 0F 85 86 01 00 00  jne         00000000000005CC
  0000000000000446: B8 01 00 00 00     mov         eax,1
  000000000000044B: 48 6B C0 04        imul        rax,rax,4
  000000000000044F: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000454: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000458: 83 F8 54           cmp         eax,54h
  000000000000045B: 0F 85 6B 01 00 00  jne         00000000000005CC
  0000000000000461: B8 01 00 00 00     mov         eax,1
  0000000000000466: 48 6B C0 05        imul        rax,rax,5
  000000000000046A: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000046F: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000473: 83 F8 68           cmp         eax,68h
  0000000000000476: 0F 85 50 01 00 00  jne         00000000000005CC
  000000000000047C: B8 01 00 00 00     mov         eax,1
  0000000000000481: 48 6B C0 06        imul        rax,rax,6
  0000000000000485: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000048A: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  000000000000048E: 83 F8 72           cmp         eax,72h
  0000000000000491: 0F 85 35 01 00 00  jne         00000000000005CC
  0000000000000497: B8 01 00 00 00     mov         eax,1
  000000000000049C: 48 6B C0 07        imul        rax,rax,7
  00000000000004A0: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000004A5: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000004A9: 83 F8 6F           cmp         eax,6Fh
  00000000000004AC: 0F 85 1A 01 00 00  jne         00000000000005CC
  00000000000004B2: B8 01 00 00 00     mov         eax,1
  00000000000004B7: 48 6B C0 08        imul        rax,rax,8
  00000000000004BB: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000004C0: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000004C4: 83 F8 77           cmp         eax,77h
  00000000000004C7: 0F 85 FF 00 00 00  jne         00000000000005CC
  00000000000004CD: B8 01 00 00 00     mov         eax,1
  00000000000004D2: 48 6B C0 09        imul        rax,rax,9
  00000000000004D6: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000004DB: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000004DF: 83 F8 45           cmp         eax,45h
  00000000000004E2: 0F 85 E4 00 00 00  jne         00000000000005CC
  00000000000004E8: B8 01 00 00 00     mov         eax,1
  00000000000004ED: 48 6B C0 0A        imul        rax,rax,0Ah
  00000000000004F1: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000004F6: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000004FA: 83 F8 78           cmp         eax,78h
  00000000000004FD: 0F 85 C9 00 00 00  jne         00000000000005CC
  0000000000000503: B8 01 00 00 00     mov         eax,1
  0000000000000508: 48 6B C0 0B        imul        rax,rax,0Bh
  000000000000050C: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000511: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000515: 83 F8 63           cmp         eax,63h
  0000000000000518: 0F 85 AE 00 00 00  jne         00000000000005CC
  000000000000051E: B8 01 00 00 00     mov         eax,1
  0000000000000523: 48 6B C0 0C        imul        rax,rax,0Ch
  0000000000000527: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000052C: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000530: 83 F8 65           cmp         eax,65h
  0000000000000533: 0F 85 93 00 00 00  jne         00000000000005CC
  0000000000000539: B8 01 00 00 00     mov         eax,1
  000000000000053E: 48 6B C0 0D        imul        rax,rax,0Dh
  0000000000000542: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000547: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  000000000000054B: 83 F8 70           cmp         eax,70h
  000000000000054E: 75 7C              jne         00000000000005CC
  0000000000000550: B8 01 00 00 00     mov         eax,1
  0000000000000555: 48 6B C0 0E        imul        rax,rax,0Eh
  0000000000000559: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000055E: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000562: 83 F8 74           cmp         eax,74h
  0000000000000565: 75 65              jne         00000000000005CC
  0000000000000567: B8 01 00 00 00     mov         eax,1
  000000000000056C: 48 6B C0 0F        imul        rax,rax,0Fh
  0000000000000570: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  0000000000000575: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000579: 83 F8 69           cmp         eax,69h
  000000000000057C: 75 4E              jne         00000000000005CC
  000000000000057E: B8 01 00 00 00     mov         eax,1
  0000000000000583: 48 6B C0 10        imul        rax,rax,10h
  0000000000000587: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  000000000000058C: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  0000000000000590: 83 F8 6F           cmp         eax,6Fh
  0000000000000593: 75 37              jne         00000000000005CC
  0000000000000595: B8 01 00 00 00     mov         eax,1
  000000000000059A: 48 6B C0 11        imul        rax,rax,11h
  000000000000059E: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000005A3: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000005A7: 83 F8 6E           cmp         eax,6Eh
  00000000000005AA: 75 20              jne         00000000000005CC
  00000000000005AC: B8 01 00 00 00     mov         eax,1
  00000000000005B1: 48 6B C0 12        imul        rax,rax,12h
  00000000000005B5: 48 8B 4C 24 28     mov         rcx,qword ptr [rsp+28h]
  00000000000005BA: 0F BE 04 01        movsx       eax,byte ptr [rcx+rax]
  00000000000005BE: 85 C0              test        eax,eax
  00000000000005C0: 75 0A              jne         00000000000005CC
  00000000000005C2: C7 44 24 70 01 00  mov         dword ptr [rsp+70h],1
                    00 00
  00000000000005CA: EB 08              jmp         00000000000005D4
  00000000000005CC: C7 44 24 70 00 00  mov         dword ptr [rsp+70h],0
                    00 00
  00000000000005D4: 0F B6 44 24 70     movzx       eax,byte ptr [rsp+70h]
  00000000000005D9: 88 44 24 38        mov         byte ptr [rsp+38h],al
  00000000000005DD: 0F B6 44 24 38     movzx       eax,byte ptr [rsp+38h]
  00000000000005E2: 85 C0              test        eax,eax
  00000000000005E4: 74 16              je          00000000000005FC
  00000000000005E6: 48 8B 44 24 68     mov         rax,qword ptr [rsp+68h]
  00000000000005EB: 48 8B 8C 24 10 01  mov         rcx,qword ptr [rsp+110h]
                    00 00
  00000000000005F3: 48 8B 49 40        mov         rcx,qword ptr [rcx+40h]
  00000000000005F7: 48 89 08           mov         qword ptr [rax],rcx
  00000000000005FA: EB 26              jmp         0000000000000622
  00000000000005FC: 48 8B 84 24 A8 00  mov         rax,qword ptr [rsp+0A8h]
                    00 00
  0000000000000604: 48 83 C0 02        add         rax,2
  0000000000000608: 48 8B D0           mov         rdx,rax
  000000000000060B: 48 8B 8C 24 B0 00  mov         rcx,qword ptr [rsp+0B0h]
                    00 00
  0000000000000613: FF 94 24 B8 00 00  call        qword ptr [rsp+0B8h]
                    00
  000000000000061A: 48 8B 4C 24 68     mov         rcx,qword ptr [rsp+68h]
  000000000000061F: 48 89 01           mov         qword ptr [rcx],rax
  0000000000000622: E9 02 FD FF FF     jmp         0000000000000329
  0000000000000627: 48 8B 44 24 60     mov         rax,qword ptr [rsp+60h]
  000000000000062C: 48 83 C0 14        add         rax,14h
  0000000000000630: 48 89 44 24 60     mov         qword ptr [rsp+60h],rax
  0000000000000635: E9 69 FC FF FF     jmp         00000000000002A3
  000000000000063A: B8 08 00 00 00     mov         eax,8
  000000000000063F: 48 6B C0 09        imul        rax,rax,9
  0000000000000643: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  0000000000000648: 83 7C 01 74 00     cmp         dword ptr [rcx+rax+74h],0
  000000000000064D: 74 70              je          00000000000006BF
  000000000000064F: B8 08 00 00 00     mov         eax,8
  0000000000000654: 48 6B C0 09        imul        rax,rax,9
  0000000000000658: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  000000000000065D: 8B 44 01 70        mov         eax,dword ptr [rcx+rax+70h]
  0000000000000661: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  0000000000000666: 48 03 C8           add         rcx,rax
  0000000000000669: 48 8B C1           mov         rax,rcx
  000000000000066C: 48 89 84 24 F0 00  mov         qword ptr [rsp+0F0h],rax
                    00 00
  0000000000000674: 48 8B 84 24 F0 00  mov         rax,qword ptr [rsp+0F0h]
                    00 00
  000000000000067C: 48 8B 40 18        mov         rax,qword ptr [rax+18h]
  0000000000000680: 48 89 44 24 78     mov         qword ptr [rsp+78h],rax
  0000000000000685: EB 0E              jmp         0000000000000695
  0000000000000687: 48 8B 44 24 78     mov         rax,qword ptr [rsp+78h]
  000000000000068C: 48 83 C0 08        add         rax,8
  0000000000000690: 48 89 44 24 78     mov         qword ptr [rsp+78h],rax
  0000000000000695: 48 83 7C 24 78 00  cmp         qword ptr [rsp+78h],0
  000000000000069B: 74 22              je          00000000000006BF
  000000000000069D: 48 8B 44 24 78     mov         rax,qword ptr [rsp+78h]
  00000000000006A2: 48 83 38 00        cmp         qword ptr [rax],0
  00000000000006A6: 74 17              je          00000000000006BF
  00000000000006A8: 45 33 C0           xor         r8d,r8d
  00000000000006AB: BA 01 00 00 00     mov         edx,1
  00000000000006B0: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000006B5: 48 8B 44 24 78     mov         rax,qword ptr [rsp+78h]
  00000000000006BA: FF 10              call        qword ptr [rax]
  00000000000006BC: 90                 nop
  00000000000006BD: EB C8              jmp         0000000000000687
  00000000000006BF: C6 44 24 20 00     mov         byte ptr [rsp+20h],0
  00000000000006C4: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  00000000000006CC: 83 78 38 00        cmp         dword ptr [rax+38h],0
  00000000000006D0: 0F 84 A8 00 00 00  je          000000000000077E
  00000000000006D6: B8 08 00 00 00     mov         eax,8
  00000000000006DB: 48 6B C0 03        imul        rax,rax,3
  00000000000006DF: 48 8B 4C 24 40     mov         rcx,qword ptr [rsp+40h]
  00000000000006E4: 48 8B 44 01 70     mov         rax,qword ptr [rcx+rax+70h]
  00000000000006E9: 48 89 84 24 90 00  mov         qword ptr [rsp+90h],rax
                    00 00
  00000000000006F1: 83 BC 24 94 00 00  cmp         dword ptr [rsp+94h],0
                    00 00
  00000000000006F9: 74 3A              je          0000000000000735
  00000000000006FB: 8B 84 24 94 00 00  mov         eax,dword ptr [rsp+94h]
                    00
  0000000000000702: 33 D2              xor         edx,edx
  0000000000000704: B9 0C 00 00 00     mov         ecx,0Ch
  0000000000000709: 48 F7 F1           div         rax,rcx
  000000000000070C: 8B 8C 24 90 00 00  mov         ecx,dword ptr [rsp+90h]
                    00
  0000000000000713: 48 8B 54 24 30     mov         rdx,qword ptr [rsp+30h]
  0000000000000718: 48 03 D1           add         rdx,rcx
  000000000000071B: 48 8B CA           mov         rcx,rdx
  000000000000071E: 4C 8B 44 24 30     mov         r8,qword ptr [rsp+30h]
  0000000000000723: 8B D0              mov         edx,eax
  0000000000000725: FF 94 24 C8 00 00  call        qword ptr [rsp+0C8h]
                    00
  000000000000072C: 85 C0              test        eax,eax
  000000000000072E: 75 05              jne         0000000000000735
  0000000000000730: C6 44 24 20 01     mov         byte ptr [rsp+20h],1
  0000000000000735: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  000000000000073D: 48 83 78 40 00     cmp         qword ptr [rax+40h],0
  0000000000000742: 74 3A              je          000000000000077E
  0000000000000744: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  000000000000074C: 48 8B 40 40        mov         rax,qword ptr [rax+40h]
  0000000000000750: 48 89 84 24 C0 00  mov         qword ptr [rsp+0C0h],rax
                    00 00
  0000000000000758: 48 8B 84 24 C0 00  mov         rax,qword ptr [rsp+0C0h]
                    00 00
  0000000000000760: 48 05 A0 00 00 00  add         rax,0A0h
  0000000000000766: 4C 8B 84 24 C0 00  mov         r8,qword ptr [rsp+0C0h]
                    00 00
  000000000000076E: BA 01 00 00 00     mov         edx,1
  0000000000000773: 48 8B C8           mov         rcx,rax
  0000000000000776: FF 94 24 C8 00 00  call        qword ptr [rsp+0C8h]
                    00
  000000000000077D: 90                 nop
  000000000000077E: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000786: 4C 8B 40 30        mov         r8,qword ptr [rax+30h]
  000000000000078A: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  0000000000000792: 8B 50 28           mov         edx,dword ptr [rax+28h]
  0000000000000795: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  000000000000079A: FF 94 24 F8 00 00  call        qword ptr [rsp+0F8h]
                    00
  00000000000007A1: 90                 nop
  00000000000007A2: 0F B6 44 24 20     movzx       eax,byte ptr [rsp+20h]
  00000000000007A7: 85 C0              test        eax,eax
  00000000000007A9: 74 12              je          00000000000007BD
  00000000000007AB: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  00000000000007B3: 48 C7 40 20 50 50  mov         qword ptr [rax+20h],505050h
                    50 00
  00000000000007BB: EB 11              jmp         00000000000007CE
  00000000000007BD: 48 8B 84 24 10 01  mov         rax,qword ptr [rsp+110h]
                    00 00
  00000000000007C5: 48 8B 4C 24 30     mov         rcx,qword ptr [rsp+30h]
  00000000000007CA: 48 89 48 20        mov         qword ptr [rax+20h],rcx
  00000000000007CE: 48 81 C4 08 01 00  add         rsp,108h
                    00
  00000000000007D5: C3                 ret

shellcode_end:
  0000000000000000: C2 00 00           ret         0

  Summary

          80 .chks64
          D4 .debug$S
          5D .drectve
          24 .pdata
         8CF .text$mn
          1A .voltbl
          18 .xdata
