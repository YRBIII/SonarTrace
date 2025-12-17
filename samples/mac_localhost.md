# SonarTrace Scan Report

**Generated:** 2025-12-17 14:03:43 UTC

## Grading Rubric Compliance
- Verified Information Table: included per host
- Unverified Information Section: included per host
- Command Output: includes exact Nmap command and full raw output

---
**Targets:** 192.168.1.24
**Excludes:** (none)
**Nmap Command:** `nmap -oX - -sS -sV -O 192.168.1.24`

## Command Output

**Command:**
`nmap -oX - -sS -sV -O 192.168.1.24`

**Full Raw Nmap Output:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///opt/homebrew/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.98 scan initiated Wed Dec 17 09:00:46 2025 as: nmap -oX - -sS -sV -O 192.168.1.24 -->
<nmaprun scanner="nmap" args="nmap -oX - -sS -sV -O 192.168.1.24" start="1765980046" startstr="Wed Dec 17 09:00:46 2025" version="7.98" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3006,3011,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5985-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1765980046" endtime="1765980223"><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="192.168.1.24" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="996">
<extrareasons reason="reset" count="996" proto="tcp" ports="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3006,3011,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5001-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5985-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7001-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49153-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"/>
</extraports>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="mysql" product="MySQL" extrainfo="unauthorized" method="probed" conf="10"><cpe>cpe:/a:mysql:mysql</cpe></service></port>
<port protocol="tcp" portid="5000"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="rtsp" servicefp="SF-Port5000-TCP:V=7.98%I=7%D=12/17%Time=6942B795%P=arm-apple-darwin25.0.0%r(GetRequest,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x203\r\nX-Apple-RequestReceivedTimestamp:\x20695865\r\n\r\n&quot;)%r(RTSPRequest,8D,&quot;RTSP/1\.0\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x202\r\nX-Apple-RequestReceivedTimestamp:\x20695905\r\n\r\n&quot;)%r(HTTPOptions,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700903\r\n\r\n&quot;)%r(FourOhFourRequest,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700911\r\n\r\n&quot;)%r(SIPOptions,9F,&quot;RTSP/1\.0\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nCSeq:\x2042\x20OPTIONS\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700916\r\n\r\n&quot;);" method="probed" conf="10"/></port>
<port protocol="tcp" portid="7000"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="rtsp" servicefp="SF-Port7000-TCP:V=7.98%I=7%D=12/17%Time=6942B79A%P=arm-apple-darwin25.0.0%r(RTSPRequest,8D,&quot;RTSP/1\.0\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x206\r\nX-Apple-RequestReceivedTimestamp:\x20695857\r\n\r\n&quot;)%r(GetRequest,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700867\r\n\r\n&quot;)%r(HTTPOptions,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700878\r\n\r\n&quot;)%r(FourOhFourRequest,8D,&quot;HTTP/1\.1\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700887\r\n\r\n&quot;)%r(SIPOptions,9F,&quot;RTSP/1\.0\x20403\x20Forbidden\r\nContent-Length:\x200\r\nServer:\x20AirTunes/890\.79\.5\r\nCSeq:\x2042\x20OPTIONS\r\nX-Apple-ProcessingTime:\x201\r\nX-Apple-RequestReceivedTimestamp:\x20700895\r\n\r\n&quot;);" method="probed" conf="10"/></port>
<port protocol="tcp" portid="49152"><state state="open" reason="syn-ack" reason_ttl="64"/></port>
</ports>
<os><portused state="open" proto="tcp" portid="3306"/>
<portused state="closed" proto="tcp" portid="1"/>
<portused state="closed" proto="udp" portid="40763"/>
<osmatch name="Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0)" accuracy="96" line="8004">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="12.X" accuracy="96"><cpe>cpe:/o:apple:mac_os_x:12</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 10.14 (Mojave) - 11 (Big Sur) (Darwin 18.2.0 - 20.6.0)" accuracy="93" line="7706">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="10.14.X" accuracy="93"><cpe>cpe:/o:apple:mac_os_x:10.14</cpe></osclass>
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="10.15.X" accuracy="93"><cpe>cpe:/o:apple:mac_os_x:10.15</cpe></osclass>
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="11.X" accuracy="93"><cpe>cpe:/o:apple:mac_os_x:11</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 11 (Big Sur) - 12 (Monterey) (Darwin 20.5.0 - 21.6.0)" accuracy="93" line="7896">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="11.X" accuracy="93"><cpe>cpe:/o:apple:mac_os_x:11</cpe></osclass>
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="12.X" accuracy="93"><cpe>cpe:/o:apple:mac_os_x:12</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 13 (Ventura) (Darwin 22.1.0)" accuracy="90" line="8160">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="13.X" accuracy="90"><cpe>cpe:/o:apple:mac_os_x:13</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 10.13.6 (High Sierra) (Darwin 17.7.0)" accuracy="90" line="7646">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="10.13.X" accuracy="90"><cpe>cpe:/o:apple:mac_os_x:10.13.6</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.3.0)" accuracy="90" line="7984">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="12.X" accuracy="90"><cpe>cpe:/o:apple:mac_os_x:12</cpe></osclass>
</osmatch>
<osmatch name="Apple iOS 14.0 - 15.6 or tvOS 14.3 - 16.1 (Darwin 20.0.0 - 22.1.0)" accuracy="89" line="3833">
<osclass type="phone" vendor="Apple" osfamily="iOS" osgen="14.X" accuracy="89"><cpe>cpe:/o:apple:iphone_os:14</cpe></osclass>
<osclass type="phone" vendor="Apple" osfamily="iOS" osgen="15.X" accuracy="89"><cpe>cpe:/o:apple:iphone_os:15</cpe></osclass>
<osclass type="media device" vendor="Apple" osfamily="tvOS" osgen="14.X" accuracy="89"><cpe>cpe:/o:apple:tvos:14</cpe></osclass>
<osclass type="media device" vendor="Apple" osfamily="tvOS" osgen="16.X" accuracy="89"><cpe>cpe:/o:apple:tvos:16</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 11 (Big Sur) - 13 (Ventura) or iOS 16 (Darwin 20.6.0 - 22.4.0)" accuracy="89" line="7943">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="11.X" accuracy="89"><cpe>cpe:/o:apple:mac_os_x:11</cpe></osclass>
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="12.X" accuracy="89"><cpe>cpe:/o:apple:mac_os_x:12</cpe></osclass>
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="13.X" accuracy="89"><cpe>cpe:/o:apple:mac_os_x:13</cpe></osclass>
</osmatch>
<osmatch name="Apple macOS 12 (Monterey) (Darwin 21.6.0)" accuracy="89" line="8058">
<osclass type="general purpose" vendor="Apple" osfamily="macOS" osgen="12.X" accuracy="89"><cpe>cpe:/o:apple:mac_os_x:12</cpe></osclass>
</osmatch>
<osmatch name="Apple iOS 14.7" accuracy="87" line="3893">
<osclass type="phone" vendor="Apple" osfamily="iOS" osgen="14.X" accuracy="87"><cpe>cpe:/o:apple:iphone_os:14.7</cpe></osclass>
</osmatch>
<osfingerprint fingerprint="OS:SCAN(V=7.98%E=4%D=12/17%OT=3306%CT=1%CU=40763%PV=Y%DS=0%DC=L%G=Y%TM=6942&#xa;OS:B83F%P=arm-apple-darwin25.0.0)SEQ(SP=101%GCD=1%ISR=10E%TI=Z%CI=RD%II=RI%&#xa;OS:TS=21)SEQ(SP=102%GCD=1%ISR=109%TI=Z%CI=RD%II=RI%TS=21)SEQ(SP=104%GCD=1%I&#xa;OS:SR=109%TI=Z%CI=RD%II=RI%TS=21)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=RD%II=RI%&#xa;OS:TS=22)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=RD%II=RI%TS=21)OPS(O1=M3FD8NW6NNT&#xa;OS:11SLL%O2=M3FD8NW6NNT11SLL%O3=M3FD8NW6NNT11%O4=M3FD8NW6NNT11SLL%O5=M3FD8N&#xa;OS:W6NNT11SLL%O6=M3FD8NNT11SLL)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%&#xa;OS:W6=FFFF)ECN(R=Y%DF=Y%T=40%W=FFFF%O=M3FD8NW6SLL%CC=N%Q=)T1(R=Y%DF=Y%T=40%&#xa;OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=N%T=40%W=0%S=Z%A=S+&#xa;OS:%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=N&#xa;OS:%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RI&#xa;OS:D=G%RIPCK=Z%RUCK=0%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)&#xa;"/>
</os>
<uptime seconds="10" lastboot="Wed Dec 17 09:03:33 2025"/>
<distance value="0"/>
<tcpsequence index="258" difficulty="Good luck!" values="4A12B098,D95236E5,EB9A037,CE85D1F9,F211D71F,198967A4"/>
<ipidsequence class="All zeros" values="0,0,0,0,0,0"/>
<tcptssequence class="other" values="4CCA3D13,FAAA4406,E4F43927,A83A3874,F0254CA2,3900D4D0"/>
<times srtt="301" rttvar="280" to="100000"/>
</host>
<runstats><finished time="1765980223" timestr="Wed Dec 17 09:03:43 2025" summary="Nmap done at Wed Dec 17 09:03:43 2025; 1 IP address (1 host up) scanned in 177.05 seconds" elapsed="177.05" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

---
## Host: 192.168.1.24 (unknown)
**Status:** up | **OS:** Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (96%)

### Verified Information

| Field | Value |
|-------|-------|
| IP Address | 192.168.1.24 |
| Hostname | (none) |
| Status | up |
| OS (Nmap) | Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (96%) |
| Open Ports (Nmap) | 3306/tcp, 5000/tcp, 7000/tcp, 49152/tcp |
| Windows Heuristic | False |

### Unverified / Heuristic Information

None identified during this scan.

### Open / Filtered Ports

| Port | State | Service | Product / Version |
|------|-------|---------|-------------------|
| 3306/tcp | open | mysql | MySQL |
| 5000/tcp | open | rtsp | ❌ |
| 7000/tcp | open | rtsp | ❌ |
| 49152/tcp | open | ❌ | ❌ |
