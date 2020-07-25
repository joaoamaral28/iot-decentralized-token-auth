# iot-decentralized-token-auth
Solution attempt for securing IoT realm applications. Developed as the practical stage of my masters degree.

# Description

Assuring security and privacy is one of the key issues affecting the Internet of Things (IoT), mostly due to its distributed nature. Therefore, for the IoT to thrive, this problem needs to be tackled and solved. This solution describes a security-oriented architecture for managing IoT deployments. Our main goal was to deal with a fine-grained control in the access to IoT data and devices, to prevent devices from being manipulated by attackers and to avoid information leaking from IoT devices to unauthorized recipients. 

The access control is split: the management of authentication and access control policies is centered on special components (Authentication, Authorization, and Accounting Controllers), which can be distributed or centralized, and the actual enforcement of access control decisions happens on the entities that stay in the path to the IoT devices (Gateways and Device Drivers).

The authentication in the entire system uses asymmetric cryptography and pre-distributed unique identifiers derived from public keys; no Public Key Infrastructure (PKI) is used. A Kerberos-like ticket-based approach is used to establish secure sessions.

This repository contains all the code developed to achieve an operational architecture that explores this state-of-the-art security solution.

* The scholar paper specifying the architecture and protocols is available at: https://www.researchgate.net/publication/336689945_Security-Oriented_Architecture_for_Managing_IoT_Deployments

* The master thesis document is publicly available in the University of Aveiro RIA platform. Link: http://hdl.handle.net/10773/28620

# The architecture

# The protocols
