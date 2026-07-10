QUIC implementation for ns-3
================================

## QUIC code base
This repository contains in the code for a native IETF QUIC implementation in ns-3.

The code implements the core transport mechanisms of [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) (loss detection and congestion control following [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002)) and works with version [ns-3.41](https://github.com/nsnam/ns-3-dev-git/tree/ns-3.41). It is a mostly compliant implementation of both RFC and can be safely used to simulate typical QUIC protocol behaviour.

The code is based on the partial implementation of the QUIC drafts described in [this paper](https://arxiv.org/abs/1902.06121) and available in https://github.com/signetlabdei/quic/tree/release-3-41

### Code Limitations
- Signaling related to security is implemented but the code does not perform encryption. This avoids unnecessary procesisng burden for a feature unnecessary for general research and networking simulation.
- Path MTU discovery is not implemented.
- Connection migration is not functional: PATH_CHALLENGE/PATH_RESPONSE frames are exchanged, but received NEW_CONNECTION_IDs are not stored/tracked and PATH_RESPONSE is not validated against a pending challenge, so there is no CID pool to migrate onto.
- A single stream is currently used. Multi stream logic is implemented internally but requires further modifications to the application-facing interface to use it.
- Explicit Congestion Notification (ECN) is not implemented; ACK_ECN frames always report zero ECT/ECN-CE counts.
- Connection IDs are fixed at 8 bytes. The variable-length (including zero-length) connection IDs allowed by RFC 9000 are not supported.
- The long header's Token and Length fields (used for Retry/0-RTT token carriage) are omitted from the wire format for simulation efficiency.
- Stateless reset is not implemented: the transport parameter is recognized, but no reset token is generated and no stateless reset packet is sent in response to an unrecognized connection ID.
- The anti-amplification check on Initial packets is a simplified packet-size floor, not the full 3x-received-bytes accounting described in RFC 9000 Section 8.1.
- The `preferred_address` transport parameter (RFC 9000 Section 18.2) is not implemented.

## Acknowledgments ##

O. Fusté, J. A. Fraire, A. Calveras, and J. A. Ruiz-de-Azúa, "Deploying QUIC in Challenged Networks: Profiling and Volume-Aware Congestion Control," in Proc. IEEE WiSEE: Space-Terrestrial Internetworking Workshop, Leuven, Belgium, 2026.

## Install

### Prerequisites ###

To run simulations using this module, you will need to install ns-3, clone this repository inside the `src` directory, copy the QUIC applications from the quic-applications folder, and patch the `wscript` file of the applications module.
Required dependencies include git and a build environment.

#### Installing dependencies ####

Please refer to [the ns-3 wiki](https://www.nsnam.org/wiki/Installation) for instructions on how to set up your system to install ns-3.

#### Downloading #####

First, clone the main ns-3 repository:

```bash
git clone https://gitlab.com/nsnam/ns-3-dev ns-3-dev
cd ns-3-dev/src
```

Then, clone the quic module:

```bash
git clone https://github.com/signetlabdei/quic quic
```

Thirdly, copy the QUIC applications and helpers to the applications module

```bash
cp quic/quic-applications/model/* applications/model/
cp quic/quic-applications/helper/* applications/helper/
```

Finally, edit the `CMakeLists.txt` file of the applications module and add

```python
        model/quic-echo-client.h
        model/quic-echo-server.h
        model/quic-client.h
        model/quic-server.h
        helper/quic-echo-helper.h
        helper/quic-client-server-helper.h
```
to the `HEADER_FILES` list and

```python
        model/quic-echo-client.cc
        model/quic-echo-server.cc
        model/quic-client.cc
        model/quic-server.cc
        helper/quic-echo-helper.cc
        helper/quic-client-server-helper.cc
```
to the `SOURCE_FILES` list.
### Compilation ###

Configure and build ns-3 from the `ns-3-dev` folder:

```bash
./ns3 configure --enable-tests --enable-examples
./ns3 build
```

If you are not interested in using the Python bindings, use

```bash
./ns3 configure --enable-tests --enable-examples --disable-python
./ns3 build
```

## Authors ##

Oriol Fusté oriol.fuste@upc.edu — Main developer  
Anna Calveras anna.calveras@upc.edu — Project supervisor  
Joan A. Ruiz-de-Azua ja.ruiz.de.azua@upc.edu — Project supervisor  

## Funding ##

This publication and other research outcomes are supported by the predoctoral program AGAUR-FI ajuts (2026 FI-3 00701) Joan Oró, which is backed by the Secretariat of Universities and Research of the Department of Research and  Universities of the Generalitat of Catalonia, as well as the European Social Plus Fund. This work is partially supported by the Spanish MCIN/AEI/ 10.13039/501100011033/FEDER/UE through project PID2023-146378NB-I00. This work has been funded by the Government of Catalonia in the scope of the Space Strategy for Catalonia 2030. We acknowledge the funding received from Department de Recerca I Universitats, Genralitat de Catalunya for this project.