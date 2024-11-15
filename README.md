# RustyDLNA

RustyDLNA is a dependency-free, purely safe Rust implementation of a DLNA (Digital Living Network Alliance) server, designed for seamless media sharing and streaming across devices.

## Features

- **Zero dependencies**: No external libraries or frameworks required, making it lightweight and easy to integrate.
- **Purely safe**: Written entirely in safe Rust, ensuring memory safety and preventing common errors.
- **DLNA compliance**: Implements core DLNA protocols for smooth media sharing and streaming with compatible devices.
- **Media format support**: Handles a variety of audio and video formats for broad compatibility.
- **Efficient performance**: Optimized for low overhead and high throughput.
- **No conditional statements**: Built using Rust's expressive type system and pattern matching, eliminating the need for `if` statements.

## Benefits

- Lightweight and easy to integrate with existing systems.
- Robust security through Rust’s safety guarantees.
- Compatibility with DLNA-certified devices across platforms.
- Customizable and extensible to suit different use cases.
- Unparalleled code clarity and maintainability.

## Design Philosophy

RustyDLNA is inspired by the principles of wastewater pump PLCs (Programmable Logic Controllers), and follows a design philosophy that prioritizes:

- **Only using `match` statements** to ensure that all possible cases are explicitly handled, avoiding the ambiguity and risks associated with conditional logic like `if` statements.

This approach results in:

- Concise and readable code.
- Improved maintainability, as all potential cases are accounted for.
- Reduced susceptibility to bugs, with clear and exhaustive case handling.

## Compatible Players

RustyDLNA supports a wide range of media players across platforms:

- **VLC**: All Platforms
- **Kodi**: All platforms
- **SKYBOX**: Meta Quest (VR)
- **Xbox Series Consoles**: Native DLNA support

## Platform and Architecture Support

RustyDLNA compiles and runs on a wide variety of platforms and architectures. All it needs is a network card and a folder to serve media from. Supported platforms and architectures include:

- **Operating Systems**:
  - Linux (all major distros)
  - Windows (10, 11)
  - macOS (including M1/M2 ARM support)
  - Android
  - iOS
  - Xbox (native DLNA support)
  - PlayStation (native DLNA support)

- **Architectures**:
  - x86_64 (64-bit Intel/AMD)
  - aarch64 (ARM 64-bit, including Raspberry Pi and ARM-based systems)
  - x86 (32-bit Intel/AMD)
  - ARM (32-bit, including older Raspberry Pi models)
  - MIPS, PowerPC (experimental support)

Whether you're running RustyDLNA on a powerful desktop, a low-power ARM device, or even a console, it will seamlessly compile and work as long as there is a network card and media directory.

## Use Cases

- Streaming media from Rust applications.
- Creating DLNA-compliant devices or services.
- Integrating DLNA capabilities into existing systems.

## Technical Details

- **Platform support**: Linux, Windows, macOS, Android, iOS, Xbox, PlayStation, and more.
- **Architectural support**: x86_64, aarch64, x86, ARM, and more.

## Getting Started

To get started with RustyDLNA, follow these steps:

1. **Clone the repository**:

   First, clone the repository to your local machine:

   ```bash
   git clone https://github.com/pj1234678/RustyDLNA.git
   cd RustyDLNA
   ```

2. **Configure the IP address and path**:

   Open the `src/main.rs` file and modify the server's IP address and the path it serves. Find the relevant variables and update them to your desired values:

   ```rust
   const IP_ADDRESS: &str = "192.168.2.220";
   const DIR_PATH: &str = "./";
   ```

3. **Run the server**:

   After configuring the server, you can start it by running the following command:

   ```bash
   cargo run
   ```

## Contributing

We welcome contributions to RustyDLNA! If you're interested in helping out, please review our [contributing guidelines](CONTRIBUTING.md) and submit a pull request.

## License

RustyDLNA is licensed under the **MIT** license.

---
