# Smart-Contract-Based-Access-Control-for-the-IoT

### 1. Framework Components:
   - Multiple Access Control Contracts (ACCs)
   - One Judge Contract (JC)
   - One Register Contract (RC)

### 2. Purpose of the Framework:
   - Aimed at achieving distributed and trustworthy access control for IoT systems.

### 3. Role of Access Control Contracts (ACCs):
   - Each ACC offers an access control method for subject-object pairs.
   - Implements both static access right validation based on predefined policies.
   - Conducts dynamic access right validation by monitoring subject behavior.

### 4. Function of the Judge Contract (JC):
   - Facilitates dynamic validation of ACCs.
   - Receives misbehavior reports from ACCs.
   - Assesses the misbehavior and imposes appropriate penalties.

### 5. Role of the Register Contract (RC):
   - Registers information related to access control and misbehavior-judging methods.
   - Stores associated smart contracts.
   - Provides functions for method management, including registration, updates, and deletions.

### 6. Demonstration of the Framework:
   - Application in an IoT system case study.
   - The case study includes devices like a desktop computer, a laptop, and two Raspberry Pi single-board computers.
   - Implementation based on the Ethereum smart contract platform for access control.