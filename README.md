# Kemon
An Open Source Pre and Post Callback-based Framework for macOS Kernel Monitoring.

[ Breaking News - 08/28/2019 ]  
macOS Catalina 10.15 Beta 7 Release Notes  
https://developer.apple.com/documentation/macos_release_notes/macos_catalina_10_15_beta_7_release_notes

Endpoint Security
 - The kauth API has been removed. (50419013)

/* After testing, I found that these Kauth interfaces are not really removed, and Kemon still works. But I think this release note means that the door to the macOS kernel is closing. (08/28/2019) */

## What is Kemon?
Kemon is an open source Pre and Post callback-based framework [1] for macOS kernel monitoring [2]. With the power of Kemon, we can easily implement XPC/IPC communication monitoring [3], Mandatory Access Control (MAC) policy filtering, network traffic and kernel extension firewall, etc. In general, from an attacker's perspective, this framework can help achieve more powerful Rootkit. From the perspective of defense, Kemon can help construct more granular monitoring capabilities.

I also implemented several kernel fuzzers [4] [7] based on this framework, which helped me find many kernel vulnerabilities, such as:

1. Apple Silicon AGX-based GPU, IOMobileFrameBuffer and Display Co-processor (DCP) [10]:  
CVE-2024-40854, CVE-2024-44197 [33], CVE-2024-44199 [34], CVE-2025-24111, CVE-2025-24257, CVE-2025-24273 [35], etc.

3. Apple's AMD and Intel-based GPU:  
CVE-2017-7155, CVE-2017-7163, CVE-2017-13883 [11], CVE-2018-4350, CVE-2018-4396, CVE-2018-4418 [12], CVE-2019-8807 [13], CVE-2022-22631, CVE-2022-22661, CVE-2022-46706 [23], etc.

4. Wi-Fi IO80211FamilyV1/V2 [5] [9]:  
CVE-2020-9832, CVE-2020-9833, CVE-2020-9834 [15], CVE-2020-9899 [16], CVE-2020-10013 [17] [18] [19], CVE-2022-26761 [24], CVE-2022-26762 [25], CVE-2022-32837, CVE-2022-32847, CVE-2022-32860 [26] [27] [28], CVE-2022-32925, CVE-2022-46709 [29] [30], CVE-2023-38610 [31] [32], etc.

5. Bluetooth Host Controller Interface (HCI) [6]:  
CVE-2020-3892, CVE-2020-3893, CVE-2020-3905, CVE-2020-3907, CVE-2020-3908, CVE-2020-3912, CVE-2020-9779, CVE-2020-9853 [14], CVE-2020-9831 [15], CVE-2020-9928, CVE-2020-9929 [16], etc.

6. Kernel memory mapping mechanism [8]:  
CVE-2020-27914, CVE-2020-27915, CVE-2020-27936 [20] [21], CVE-2021-30678 [22], etc.

## Supported Features
Kemon's features include：
- file operation monitoring
- process creation monitoring
- dynamic library and kernel extension monitoring
- network traffic monitoring
- Mandatory Access Control (MAC) policy monitoring, etc.

In addition, Kemon project can also extend the Pre and Post callback-based monitoring interfaces for any macOS kernel function.

## Getting Started
### How to build the Kemon kernel extension
Please use Xcode project or makefile to build the Kemon kext driver

### How to use the Kemon kernel extension
Please turn off macOS System Integrity Protection (SIP) check if you don't have a valid kernel certificate  
Use the command "sudo chown -R root:wheel kemon.kext" to change the owner of the Kemon kernel extension  
Use the command "sudo kextload kemon.kext" to install the Kemon kernel extension  
Use the command "sudo kextunload kemon.kext" to uninstall the Kemon kernel extension


## Contributing
Welcome to contribute by creating issues or sending pull requests. See Contributing Guide for guidelines.

## License
Kemon is licensed under the Apache License 2.0. See the LICENSE file.

## References
1. https://patents.google.com/patent/US11106491B2
2. https://www.blackhat.com/us-18/arsenal/schedule/#kemon-an-open-source-pre-and-post-callback-based-framework-for-macos-kernel-monitoring-12085
3. https://www.blackhat.com/us-19/arsenal/schedule/#ksbox-a-fine-grained-macos-malware-sandbox-15059
4. https://www.defcon.org/html/defcon-26/dc-26-speakers.html#Wang
5. https://www.blackhat.com/us-20/briefings/schedule/index.html#dive-into-apple-iofamilyv-20023
6. https://www.blackhat.com/eu-20/briefings/schedule/index.html#please-make-a-dentist-appointment-asap-attacking-iobluetoothfamily-hci-and-vendor-specific-commands-21155
7. https://www.blackhat.com/us-20/arsenal/schedule/index.html#macos-bluetooth-analysis-suite-mbas-19886
8. https://www.blackhat.com/asia-21/briefings/schedule/index.html#racing-the-dark-a-new-tocttou-story-from-apples-core-22214
9. https://www.blackhat.com/us-22/briefings/schedule/#dive-into-apple-iofamily-vol--27728
10. https://www.blackhat.com/us-25/briefings/schedule/index.html#dead-pixel-detected---a-security-assessment-of-apples-graphics-subsystem-45392
11. https://support.apple.com/en-us/HT208331
12. https://support.apple.com/en-us/HT209193
13. https://support.apple.com/en-us/HT210722
14. https://support.apple.com/en-us/HT211100
15. https://support.apple.com/en-us/HT211170
16. https://support.apple.com/en-us/HT211289
17. https://support.apple.com/en-us/HT211843
18. https://support.apple.com/en-us/HT211849
19. https://support.apple.com/en-us/HT211850
20. https://support.apple.com/en-us/HT211931
21. https://support.apple.com/en-us/HT212011
22. https://support.apple.com/en-us/HT212529
23. https://support.apple.com/en-us/HT213183
24. https://support.apple.com/en-us/HT213257
25. https://support.apple.com/en-us/HT213258
26. https://support.apple.com/en-us/HT213346
27. https://support.apple.com/en-us/HT213345
28. https://support.apple.com/en-us/HT213344
29. https://support.apple.com/en-us/HT213446
30. https://support.apple.com/en-us/HT213486
31. https://support.apple.com/en-us/HT213938
32. https://support.apple.com/en-us/HT213940
33. https://support.apple.com/en-us/121564
34. https://support.apple.com/en-us/120911
35. https://support.apple.com/en-us/122373
