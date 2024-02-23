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

1. Graphics related kernel extensions:  
CVE-2017-7155, CVE-2017-7163, CVE-2017-13883 [10], CVE-2018-4350, CVE-2018-4396, CVE-2018-4418 [11], CVE-2019-8807 [12], CVE-2022-22631, CVE-2022-22661, CVE-2022-46706 [22], etc.

2. Wi-Fi IO80211FamilyV1/V2 [5] [9]:  
CVE-2020-9832, CVE-2020-9833, CVE-2020-9834 [14], CVE-2020-9899 [15], CVE-2020-10013 [16] [17] [18], CVE-2022-26761 [23], CVE-2022-26762 [24], CVE-2022-32837, CVE-2022-32847, CVE-2022-32860 [25] [26] [27], CVE-2022-32925, CVE-2022-46709 [28] [29], CVE-2023-38610 [30] [31], etc.

3. Bluetooth Host Controller Interface (HCI) [6]:  
CVE-2020-3892, CVE-2020-3893, CVE-2020-3905, CVE-2020-3907, CVE-2020-3908, CVE-2020-3912, CVE-2020-9779, CVE-2020-9853 [13], CVE-2020-9831 [14], CVE-2020-9928, CVE-2020-9929 [15], etc.

4. Kernel memory mapping mechanism [8]:  
CVE-2020-27914, CVE-2020-27915, CVE-2020-27936 [19] [20], CVE-2021-30678 [21], etc.

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
10. https://support.apple.com/en-us/HT208331
11. https://support.apple.com/en-us/HT209193
12. https://support.apple.com/en-us/HT210722
13. https://support.apple.com/en-us/HT211100
14. https://support.apple.com/en-us/HT211170
15. https://support.apple.com/en-us/HT211289
16. https://support.apple.com/en-us/HT211843
17. https://support.apple.com/en-us/HT211849
18. https://support.apple.com/en-us/HT211850
19. https://support.apple.com/en-us/HT211931
20. https://support.apple.com/en-us/HT212011
21. https://support.apple.com/en-us/HT212529
22. https://support.apple.com/en-us/HT213183
23. https://support.apple.com/en-us/HT213257
24. https://support.apple.com/en-us/HT213258
25. https://support.apple.com/en-us/HT213346
26. https://support.apple.com/en-us/HT213345
27. https://support.apple.com/en-us/HT213344
28. https://support.apple.com/en-us/HT213446
29. https://support.apple.com/en-us/HT213486
30. https://support.apple.com/en-us/HT213938
31. https://support.apple.com/en-us/HT213940
