# ASSIGNMENT 3: TCP Three-Way Handshake using Raw Sockets

## Authors: Ekansh Bajpai (220390), Pulkit Dhayal (220834)

## Course: CS425 - Computer Networks  
**Instructor:** Adithya Vadapalli  
**TAs In-Charge:** Mohan, Viren, Prakhar  
---

## Overview
This assignment implements the **client-side** of a simplified **TCP three-way handshake** using **raw sockets in C++**. The goal is to understand low-level TCP communication by manually crafting and parsing packets. The **server-side** code is provided and must be used as-is.

---

## Prerequisites

- A Linux environment (raw sockets require root access and Linux-style headers)
- C++ compiler (e.g., `g++`)
- Root privileges to run the programs
- Git (to clone the official repo)

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/privacy-iitk/cs425-2025.git
cd cs425-2025/Homeworks/A3
```

### 2. Add/Replace Files
Place your modified `client.cpp` in the same directory as the provided `server.cpp`.

### 3. Compile the Programs
```bash
sudo g++ server.cpp -o server
sudo g++ client.cpp -o client
```

> Using `sudo` to compile and run since raw sockets require elevated permissions.

---

## Usage Instructions

### 1. Run the Server (Terminal 1)
```bash
sudo ./server
```

### 2. Run the Client (Terminal 2)
```bash
sudo ./client
```

---

## Implementation Details

### 🔧 Three-Way Handshake Process
1. **SYN**: The client sends a SYN packet to initiate the connection.
2. **SYN-ACK**: The server responds with a SYN-ACK packet.
3. **ACK**: The client sends the final ACK to complete the handshake.

- The server handles only one connection at a time.
- The client and server exchange fixed values for sequence numbers, which can be verified in `server.cpp`.

### 🧠 Raw Socket Usage
- Manual construction of IP and TCP headers
- Manual setting of flags (SYN, ACK)
- Calculation of checksums
- Parsing of packet data at the byte level

---

## Error Handling

- The program checks for common errors like:
  - Failure to create raw socket
  - Malformed packets
  - Invalid or unexpected responses from the server

- All critical operations are guarded with basic `cerr` logging to help trace issues.

---

## File Structure

```
A3/
│── client.cpp       # C++ code implementing TCP client using raw sockets
│── server.cpp       # Provided server code (do not modify)
│── README.md        # Documentation (this file)
```

---

## Grading Criteria

| Component         | Weight |
|------------------|--------|
| Correctness      | 60%    |
| Code Comments    | 15%    |
| Documentation    | 25%    |

---

## Submission Instructions

1. Zip the following files:
   - `client.cpp`
   - `README.md`

2. Use the naming convention:
   ```
   A3<RollNo1><RollNo2><RollNo3>.zip
   ```
   *Example:* `A3220390220834.zip`

3. Uplo
---

## Notes

- All clarifications should be sought on **Piazza**.
- Ensure that the server is running before starting the client.
- Do not use advanced TCP libraries; stick to **raw sockets** and **manual packet crafting** as required.

---

Happy Packet Crafting! 📡
