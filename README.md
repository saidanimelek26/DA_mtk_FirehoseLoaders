# Notes About the Included Files

The original files included in this repository were primarily extracted from **AMT DUMP**. As for the newer files, they have been added through my own research and work. I continuously try to collect, analyze, create, and contribute any files that may be useful to the community.

## EMMC DRIVER

The **EMMC DRIVER** section is the most important part of this repository.

The drivers provided here should be considered **reference implementations**. While they are functional, they may require modifications before they can be used to build a new **Preloader**. The required changes depend on the Android source tree and the specific Preloader source you are using.

Before using any driver, **always verify the SoC/processor name** associated with the file. The extraction tool I use is not completely accurate, so some filenames or detected chip names may be incorrect.

For the best results:

* Check the **XLS configuration** included in your Preloader source tree.
* Compare it with the driver provided here.
* Modify the driver so that it matches your target device's memory configuration.

## If You Want to Create a New EMI Configuration

There are two possible approaches:

### 1. Use EMI EXIT

This repository includes the **EMI EXIT** utility inside the **TOOLS** directory.

If your device has an available **XLS** configuration file, this tool may help you generate or analyze the required EMI settings.

### 2. Extract Information from the Original Preloader

If no XLS configuration exists for your device, it usually means the EMI configuration has not yet been extracted from its original Preloader.

For this situation, I have included a small utility that extracts a large amount of useful information from the Preloader. This information can be used as a starting point when recreating the EMI driver.

Please note that this tool is **not yet complete**. Due to limited time, I have not been able to continue its development or improve its capabilities.

## About EMI EXIT

The **EMI EXIT** utility dates back to **2016**. Its limited compatibility with newer devices is likely caused by changes introduced in modern MediaTek platforms, such as updated memory initialization methods, structures, or embedded addresses.

If anyone is interested in reverse engineering the program and understanding its internal logic, it would be a valuable contribution to the community and could significantly improve support for newer devices.

## Contributing

If you have any questions, suggestions, or would like to contribute to improving this project and supporting the MediaTek community, feel free to contact me.

**Telegram:** @Meleksaidanidevmtk
**Facebook:** https://www.facebook.com/no.idea.120/
**AmtDump:** https://archive.diablosat.cc/firmwares/amt-dumps/
**emiexit:** https://4pda.to/forum/index.php?showtopic=583114&st=9480#entry54676285
Thank you for your support.
