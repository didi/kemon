# Kemon
An Open Source Pre and Post Callback-based Framework for macOS Kernel Monitoring.

[ Breaking News - 08/28/2019 ]  
macOS Catalina 10.15 Beta 7 Release Notes  
https://developer.apple.com/documentation/macos_release_notes/macos_catalina_10_15_beta_7_release_notes

Endpoint Security
 - The kauth API has been removed. (50419013)

/* After testing, I found that these Kauth interfaces are not really removed, and Kemon still works. But I think this release note means that the door to the macOS kernel is closing. (08/28/2019) */

## What is Kemon?
Kemon is an open source Pre and Post callback-based framework for macOS kernel monitoring [1]. With the power of Kemon, we can easily implement XPC/IPC communication monitoring [2], Mandatory Access Control (MAC) policy filtering, network traffic and kernel extension firewall, etc. In general, from an attacker's perspective, this framework can help achieve more powerful Rootkit. From the perspective of defense, Kemon can help construct more granular monitoring capabilities.

I also implemented several kernel fuzzers [3] [6] based on this framework, which helped me find many kernel vulnerabilities, such as:

1. Graphics related kernel extensions:  
CVE-2017-7155, CVE-2017-7163, CVE-2017-13883 [9], CVE-2018-4350, CVE-2018-4396, CVE-2018-4418 [10], CVE-2019-8807 [11], etc.

2. Wi-Fi IO80211FamilyV1/V2 [4] [8]:  
CVE-2020-9832, CVE-2020-9833, CVE-2020-9834 [13], CVE-2020-9899 [14], CVE-2020-10013 [15] [16] [17], CVE-2022-26761 [21], CVE-2022-26762 [22], etc.

3. Bluetooth Host Controller Interface (HCI) [5]:  
CVE-2020-3892, CVE-2020-3893, CVE-2020-3905, CVE-2020-3907, CVE-2020-3908, CVE-2020-3912, CVE-2020-9779, CVE-2020-9853 [12], CVE-2020-9831 [13], CVE-2020-9928, CVE-2020-9929 [14], etc.

4. Kernel memory mapping mechanism [7]:  
CVE-2020-27914, CVE-2020-27915, CVE-2020-27936 [18] [19], CVE-2021-30678 [20], etc.

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
1. https://www.blackhat.com/us-18/arsenal/schedule/#kemon-an-open-source-pre-and-post-callback-based-framework-for-macos-kernel-monitoring-12085
2. https://www.blackhat.com/us-19/arsenal/schedule/#ksbox-a-fine-grained-macos-malware-sandbox-15059
3. https://www.defcon.org/html/defcon-26/dc-26-speakers.html#Wang
4. https://www.blackhat.com/us-20/briefings/schedule/index.html#dive-into-apple-iofamilyv-20023
5. https://www.blackhat.com/eu-20/briefings/schedule/index.html#please-make-a-dentist-appointment-asap-attacking-iobluetoothfamily-hci-and-vendor-specific-commands-21155
6. https://www.blackhat.com/us-20/arsenal/schedule/index.html#macos-bluetooth-analysis-suite-mbas-19886
7. https://www.blackhat.com/asia-21/briefings/schedule/index.html#racing-the-dark-a-new-tocttou-story-from-apples-core-22214
8. https://www.blackhat.com/us-22/briefings/schedule/#dive-into-apple-iofamily-vol--27728
9. https://support.apple.com/en-us/HT208331
10. https://support.apple.com/en-us/HT209193
11. https://support.apple.com/en-us/HT210722
12. https://support.apple.com/en-us/HT211100
13. https://support.apple.com/en-us/HT211170
14. https://support.apple.com/en-us/HT211289
15. https://support.apple.com/en-us/HT211843
16. https://support.apple.com/en-us/HT211849
17. https://support.apple.com/en-us/HT211850
18. https://support.apple.com/en-us/HT211931
19. https://support.apple.com/en-us/HT212011
20. https://support.apple.com/en-us/HT212529
21. https://support.apple.com/en-us/HT213257
22. https://support.apple.com/en-us/HT213258
