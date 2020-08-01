# iot-decentralized-token-auth
Solution attempt for securing IoT realm applications. Developed as the practical stage of my masters degree thesis.

# Project description

Assuring security and privacy is one of the key issues affecting the Internet of Things (IoT), mostly due to its distributed nature. Therefore, for the IoT to thrive, this problem needs to be tackled and solved. This solution describes a security-oriented architecture for managing IoT deployments. Our main goal was to deal with a fine-grained control in the access to IoT data and devices, to prevent devices from being manipulated by attackers and to avoid information leaking from IoT devices to unauthorized recipients. 

The access control is split: the management of authentication and access control policies is centered on special components (Authentication, Authorization, and Accounting Controllers), which can be distributed or centralized, and the actual enforcement of access control decisions happens on the entities that stay in the path to the IoT devices (Gateways and Device Drivers).

The authentication in the entire system uses asymmetric cryptography and pre-distributed unique identifiers derived from public keys; no Public Key Infrastructure (PKI) is used. A Kerberos-like ticket-based approach is used to establish secure sessions.

This repository contains all the code developed to achieve an operational architecture that explores this state-of-the-art security solution.

* The scholar paper specifying the architecture and protocols is available at: https://www.researchgate.net/publication/336689945_Security-Oriented_Architecture_for_Managing_IoT_Deployments

* The master thesis document is publicly available in the University of Aveiro RIA platform. Link: http://hdl.handle.net/10773/28620

# Architecture

The architecture of the system and its underlying communications can be abstracted with the following image: 

<p align="center">
<img src="https://github.com/joaoamaral28/iot-decentralized-token-auth/blob/master/figs/architecture.png" width=500px>
</p>

In the practical implementation the GW entity was deployed in a RaspberryPi 3 and the DH entity deployed in a 32 bit microcontroller. 
The GW <-> DH communication was performed via Bluetooth Low Energy (BLE). All the remaining communication is done via IP.

Note that this solution was only considered for Local Area Network scenarios. Optimally, some of the architectural entities would be deployed outside the LAN or even hosted in cloud based services, however, although reasonable, this was not considered for the scope of the project. 

# Workflow

## Network bootstrap and configuration

<p align="center">
<img src="https://github.com/joaoamaral28/iot-decentralized-token-auth/blob/master/figs/workflow_bootstrap.png" width=600px>
</p>

## Client-DD session setup 

<p align="center">
<img src="https://github.com/joaoamaral28/iot-decentralized-token-auth/blob/master/figs/workflow_auth.png" width=600px>
</p>

# Protocols

## Ticket fetching protocol
<!---
<p align="center">
<img src="https://github.com/joaoamaral28/iot-decentralized-token-auth/blob/master/figs/protocol_ticket_fetch.png" width=400px>
</p>
-->

The ticket fetching protocol is a fast, two message protocol which allows
an entity, known here as the ticket owner (O), to obtain a ticket to be used in order to access
another entity, considered the ticket target (T). This ticket is issued by the A3C server of its
corresponding target entity.

| Entity | Operation |
| :---:  |     :---      |
| O | Generate a random R<sub>1</sub>|
| O &rarr; A3C | K<sup>+</sup><sub>O</sub>, UUID<sub>T</sub>, { R<sub>1</sub> } <sub>K<sup>+</sup><sub>A3C</sub> </sub>
| A3C| Checks if UUID<sub>O</sub> can access UUID<sub>T</sub> <br> Recover R<sub>1</sub> with K<sup>-</sup><sub>A3C</sub> <br> Generate random R<sub>2</sub> <br> Computes K = R<sub>1</sub> ⊕ R<sub>2</sub> <br> Generate T<sub>A3C</sub> [ O &rarr; T, K ] with K<sup>+</sup><sub>T</sub> |
| O &larr; A3C | { R<sub>2</sub> } K<sup>+</sup><sub>O</sub>, T<sub>A3C</sub> [ O &rarr; T, K ], K<sup>+</sup><sub>A3C</sub> |
| O | Recovers R<sub>2</sub> with K<sup>-</sup><sub>O</sub> <br> Computes K = R<sub>1</sub> ⊕ R<sub>2</sub>  |

### Ticket structure

Each ticket used in the architecture possesses the same three parted structure: a secret or
private part, a public part and a signature part.

The secret part contains a confidential master key used for the establishment of secure
sessions with regards to data encryption and integrity. When the issued ticket is received and
validated by its target entity, the session key will then be used for securing such session until
it expires. The ticket private part is always encrypted with the public key of the ticket target
(K<sup>+</sup><sub>target</sub>).

The public part contains all the data in the communications procedures involving the
ticket that do not require any sort of confidentiality. This usually includes the ticket target
identifier (ID), a pseudonym of the ticket owner, the ticket expiration date and the set of
rights the ticket owner has over the target.

The signature part contains the signature of the ticket and is performed by the entity
issuing it over the other two parts, secret and private. The signature is computed with the
private key of the ticket issuer (K<sup>-</sup><sub>issuer</sub>).


## Session setup protocol 
<!---
<p align="center">
<img src="https://github.com/joaoamaral28/iot-decentralized-token-auth/blob/master/figs/protocol_session_setup.png" width=400px>
</p>
-->

The session creation protocol, is a three-way handshake which, similarly to
the ticket fetching protocol, uses a ticket and two random values, R<sub>1</sub> and R<sub>2</sub>, in order to
create a derived session key, K'
, obtained from the original master session key K, present
inside the ticket secret part, already owned by the session requester.

| Entity | Operation |
| :---:  |     :---      |
| I | Generates a random R<sub>1</sub> | 
| I &rarr; T | T<sub>A3C</sub> [ I &rarr; T, K ], K<sup>+</sup><sub>A3C</sub>, R<sub>1</sub> |
| T | Check if K<sup>+</sup><sub>A3C</sub> matches its UUID<sub>A3C</sub> <br> Validates ticket signature with K<sup>+</sup><sub>A3C</sub> <br> Recovers K from the ticket secret part with K<sup>-</sup><sub>T</sub> <br> Generate random R<sub>2</sub> <br> Computes K<sup>'</sup> = digest(K, R<sub>1</sub>, R<sub>2</sub> ) |
| I &larr; T | R<sub>2</sub>, { R<sub>1</sub> } <sub>K'</sub> |
| I| Computes K<sup>'</sup>|
| I &rarr; T | { R<sub>2</sub> } <sub>K'</sub>  |
