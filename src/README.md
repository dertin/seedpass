# 🌱 SeedPass - Secure and Reproducible Password Generator

**SeedPass** is a command-line tool written in **Rust** that securely generates deterministic passwords using a master key. It supports **BIP-39 mnemonic phrases** as well as custom keys. The tool leverages **Argon2id** for password derivation, **HMAC-SHA3-512** for deterministic salt generation, and ensures high security with built-in entropy validation and memory-safe operations. Users can include optional context and pepper values to enhance password uniqueness and security.

## ⚠️ Disclaimer

**SeedPass is currently in development and provided "as is" without any guarantees.**  
Users are responsible for securely managing their master keys and generated passwords.  
Always store your master key and pepper in secure offline locations to avoid unauthorized access.  
**Use this tool at your own risk.**

## ⚠️ Security Recommendations <a name="recommendations"></a>

- **Master Key:** Store your master key in a secure physical medium, such as a **steel wallet**, to ensure its long-term safety.
- **Pepper:** It is recommended to store your pepper securely on a metal-engraved card or another durable offline medium. You can choose a value that you can remember, but this is not mandatory. Ensure it is sufficiently complex and not easily guessable.
- **Regeneration:** To regenerate a password, you must have your master key, pepper, and the exact service name, context value, and password length used during the original generation. Keeping these details securely stored ensures you can recover your passwords whenever needed.
- **Air Gap Environment:** Operate SeedPass on a dedicated device that is completely disconnected from any network, especially the internet. This minimizes exposure to potential cyber threats and ensures that sensitive information, such as your master key and generated passwords, remains secure.
- **Recommended Hardware:** It is recommended to use single-board computers with at least 16GB of RAM for optimal performance, such as the Raspberry Pi 5 or Orange Pi 5 Plus. These devices can be configured as secure, isolated environments for password generation tasks.
- **Secure Password Manager**: It is recommended to store generated passwords in a secure password manager like **KeePass XC**, and use SeedPass only when necessary to regenerate a lost password or to create a new one. This ensures minimal exposure of your master key and other sensitive data while maintaining ease of access to your credentials.

## 💻 Usage <a name="usage"></a>

To use `SeedPass`, follow these steps:

### 1. **Install SeedPass with Cargo:**
```bash
cargo install seedpass
```

### 2. **Generate a password:**  
Run the following command to generate a password for a service using your master key:

```bash
seedpass --master-key "your BIP-39 mnemonic phrase" --service "example.com"
```

_Example with optional parameters:_

```bash
seedpass --master-key "your BIP-39 mnemonic phrase" --service "github.com" \
            --pepper "extra_security" --context "@dertin-1" --length 32
```

### 3. **Parameters available:**

| Parameter                  | Description                                                     | Default Value |
|----------------------------|-----------------------------------------------------------------|---------------|
| `--master-key`              | The master key (BIP-39 mnemonic phrase) used to derive passwords | *Required*    |
| `--service`                 | The service name for which the password is generated             | *Required*    |
| `--pepper`                  | An optional value to further enhance security                    | None          |
| `--context`                 | Additional context to ensure uniqueness (e.g. username, timestamp, counter) | None          |
| `--length`                  | Desired length of the generated password                         | 64            |
| `--allow-master-key-no-bip39`| Allows using a non-BIP-39 master key                              | false         |


### 4. **Regenerating passwords**

To regenerate the same password for a service, you must provide the exact values used during its initial generation. This includes:

- **Master Key**: Your secure BIP-39 mnemonic phrase or custom key.
- **Pepper** (if used): The exact pepper value used to enhance security.
- **Service Name**: The exact name or identifier of the service (e.g., website URL, app name).
- **Context**: (if used) The exact identifier provided (e.g., username, timestamp, or unique descriptor).
- **Password Length**: The desired length of the generated password.

> ### ⚠️ Important
> These values are **as crucial as your master key and pepper.**  
> Without them, **you will not be able to regenerate the same password.**  
> 💾 Please store records of the **service name**, **context**, and **password length** in a **safe and retrievable location**.

_Example of regenerating the same password:_

```bash
seedpass --master-key "your BIP-39 mnemonic phrase" --service "example.com" --context "user123"
seedpass --master-key "your BIP-39 mnemonic phrase" --service "example.com" --context "user123"
```
The output will be the same password in both cases, ensuring you can reliably retrieve your credentials whenever needed.

#### Updating passwords for a service:

If a service requires you to change your password, you can keep the same master key, pepper, and service name while updating the `--context` parameter. This allows you to generate a new password while preserving a consistent structure.

_Example of updating passwords for a service:_

```bash
seedpass --master-key "your BIP-39 mnemonic phrase" --service "example.com" --context "user123-1"
seedpass --master-key "your BIP-39 mnemonic phrase" --service "example.com" --context "user123-2"
```

**In this case:**

- The context is updated with an incremental value (user123-1, user123-2), allowing the generation of a new password without losing track of previous ones.

**Recommendations:**

- Choose a consistent context format to track password changes effectively (e.g., username-1, username-2, or service-date).
- Store older context values securely for reference in case a rollback is needed.

## 🔐 Security Features <a name="security"></a>

SeedPass is designed with security in mind, offering the following features:

- **Argon2 Key Derivation:** Uses Argon2id with configurable parameters for memory-hard password derivation.
- **BIP-39 Mnemonic Support:** Allows the use of a secure mnemonic phrase as the master key.
- **Pepper and Context:** Optional pepper and context values to increase password uniqueness.
- **Minimum Entropy Checks:** Ensures strong entropy requirements for master keys and passwords.
- **Zeroization:** Sensitive data is securely erased from memory after use.

## 🐳 Docker Support <a name="docker"></a>

You can also run SeedPass inside a Docker container:

1. **Build the Docker image for ARM64 architecture (e.g., Raspberry Pi, Orange Pi):**
```bash
docker buildx build --platform linux/arm64 -t seedpass-arm64-musl --load .
```

2. **Run SeedPass inside the container:**
```bash
docker run --rm --platform=linux/arm64 seedpass-arm64-musl /usr/local/bin/seedpass --help
```

## 🚀 Roadmap <a name="roadmap"></a>

Check out the [milestones](https://github.com/dertin/seedpass/milestones) for upcoming features and releases.

- [ ] Enhance README and documentation (include additional usage examples, best security practices, and troubleshooting).
- [ ] Provide configuration options for Argon2 parameters (memory cost, iterations, parallelism).
- [ ] Ensure compatibility and performance optimizations for ARMv8-A architecture on devices such as Raspberry Pi and Orange Pi.
- [ ] Release the first stable version with full ARMv8-A support.
- [ ] Implement continuous integration and testing pipelines (CI/CD) for cross-platform validation.

## ❓ Troubleshooting <a name="troubleshooting"></a>

If you encounter any issues or have questions, please open an issue on the GitHub repository.

## 💫 Contributions <a name="contributions"></a>

Contributions make the open-source community thrive. Your contributions to `SeedPass` are **greatly appreciated**!

To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a pull request.

For issues or suggestions, please open an issue with appropriate labels.

**Don't forget to star the project!**

## 🧪 Testing <a name="testing"></a>

Run tests to ensure everything is working correctly:

```bash
cargo test
```

## 📚 License

SeedPass is licensed under the MIT or Apache-2.0 License. You are free to use, modify, and distribute it under the terms of these licenses.

## 📈 Contact

For questions or support, please open an issue on the GitHub repository.

---

Thank you for using **SeedPass** and ensuring your online security!