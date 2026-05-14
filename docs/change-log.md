# Change Log & Release Notes

This document contains a summary of the new features, changes, fixes and known
issues in each release of Hafnium.

## [2.15.0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/refs/tags/v2.14.0..refs/tags/v2.15.0) (2026-05-26)

### Highlights

* Memory Management Enhancements:
    * Introduced new memory allocator APIs to improve flexibility and allocator
      handling across Hafnium components.

* Developer Experience Improvements:
    * Introduced multiple framework, tooling, and infrastructure improvements
      across Hafnium to enhance developer productivity, usability, and overall
      workflow experience.

* SP Live Activation Support:
    * Added support for Secure Partition (SP) live activation.
    * Added support for extended partition info descriptors from FF-A v1.3 spec.

* Secure Partition Enhancements:
    * Added support for canonical UUID format handling.
    * Added support for the FF-A v1.1 partition manifest services structure to
      better associate service UUIDs with their messaging methods.

* Service Protocol Improvements:
    * Added support to explicitly specify the messaging method for each service
      protocol UUID.

* Build & CI Improvements:
    * Added a Jenkins job to execute TF-A/TFTF SPM test groups from Hafnium CI
      using Shrinkwrap on FVP.

### Features

* **api:** hypervisor rx/tx buffer reporting ([bc001f6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bc001f6e8b130bcd63165407f1873094ededb33b))
* **api:** use the rollback functionality from memory allocator ([97f0624](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/97f0624726b576503f59d42c00624ea1d643f3ad))
* **arch/cpu:** define arch_current_cpu() ([404bca0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/404bca0c32af0d7afe3c3edb3d6a595c62dc9900))
* **arch/vcpu:** define 'arch_vcpu_get_current' ([d528926](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d528926ee724efb9e90c4162364647731f494c72))
* **commitlint:** add commitlint-branch target to Makefile ([45e22ab](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/45e22ab75c9b4d103334b43a407813f448a9ca7a))
* **ff-a:** helpers for compatibility between old and new descriptors ([8de6fc5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8de6fc56c5d185b33bc371071a8e2aa20c5b37f3))
* **ff-a:** report image UUID during partition discovery ([0b40335](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0b40335fde11ebfe64800148300cf43b3f05abca))
* **ff-a:** report live activation in partition info descriptor ([bcd15f2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bcd15f256e09b6d3f3e14fcc1e79ff61a43bcc0a))
* **ff-a:** support extended partition info descriptor ([4e80e89](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4e80e8905509a848a4f2c99c66608b032429a0b8))
* **ffa_memory:** use memory allocator for region fragments ([5941cc2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5941cc2720e6a9b8953d51bcbba6078bba500433))
* **ffa_memory:** use the rollback functionality from memory allocator ([d82b93c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d82b93cc29fc5c5fc75997c38b1e9b784ed2db58))
* **hftest:** integrate dual-UART logs & skip unsupported SP-to-SP tests ([8d11d70](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8d11d70912556f055c99a4bd365f6840c3fa68b9))
* **hftest:** memory allocator for the tests ([09bcb30](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/09bcb30a1852a263fb594e4a048d72d012f26392))
* **hftest:** test partitions depend on memory allocator ([000dadb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/000dadb58ae1b758a55a7dccfb82befdc33d913e))
* **kokoro:** add --suite and --test options ([3b3e178](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3b3e17877dfdea9067ca09ecf681f9721aa61e23))
* **kokoro:** use per-test log directories to prevent overwrites ([da3708d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/da3708dcd2407da4847ad05cabf0f9632972a905))
* **lfa:** allocate CPU cyles to initialize new SP instance ([b8bb4eb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b8bb4eb579ca63369379025a900fdc0041dd4792))
* **lfa:** complete SP live activation and send response to LSP ([6d21674](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6d2167486ca961f0909aebc953b6c5985ca4cfb7))
* **lfa:** expect live state buffer in partition manifest ([127a924](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/127a924a51615eeffbeadf00af0213e056cde13f))
* **lfa:** inform LSP about fatal errors while live activating SP ([e91194d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e91194d64a76d6ecde95a527b62f1eefb13c37e2))
* **lfa:** introduce global live activation tracker ([3d13914](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3d139149767e179c866af0da400a3f89eea26fdb))
* **lfa:** introduce support for lifecycle framework message ABIs ([3d9e566](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3d9e56694c6d2c44e286e27bf2a2ca050253bf42))
* **lfa:** prepare to stop SP for live activation ([2242e90](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2242e90b3409234885e920e72ac453bfcd12045e))
* **lfa:** receive stop response for live activation ([f0a062a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f0a062a45c421855272ea0f86255ffbbbf7a0845))
* **lfa:** support live activation finish request ([04e9ffa](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/04e9ffa1f8b38f1cf255bb68b90324d934f49574))
* **lfa:** support live activation start request message ([e9339d6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e9339d6750cc36e2f38e8fb90599ad5fbb8c648f))
* **lfa:** validate partition stop response and prepare new instance ([22e0b7c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/22e0b7ca29b43f7f545068fd1b89dbc9c14deb2b))
* **lifecycle:** restrict FFA_ABORT to v1.3 compliant SPs ([103efb4](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/103efb4ab7880f67f29d7a8b5f14a5b6fb04cb16))
* **manifest:** add services struct for v1.1 manifests ([19c087e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/19c087e2b39a5b8900fe877083ebcbc8845cabdd))
* **manifest:** add support for live activation fields ([9b661ba](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9b661ba11d8f212a0204d4aba26e3cb95a0cb078))
* **manifest:** add UUID specific messaging methods ([dc52069](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/dc5206961a3b420973e4445903708c732b369fac))
* **manifest:** check for duplicate UUIDs within SP manifest ([b1d0c63](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b1d0c633282e52377de882e86473f623beaeeb80))
* **manifest:** move to canonical string UUID for v1.1 manifest ([5d771ce](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5d771ce445dc835c1bc490545d9d212edbd7e061))
* **manifest:** support for canonical image uuid parsing ([acb5167](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/acb5167153c6b77e9ac9d77e6c7874fb74970d8e))
* **manifest:** support for parsing image uuid ([fdfdee7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fdfdee708cd591eda86ac66c0b91960e7631ce3d))
* **memory_alloc:** add rollback allocator using per-CPU mem pools ([5283e32](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5283e32b2fab048f6bdb9197befc57cb5d4db235))
* **memory_alloc:** add temporary API to get ppool ([b1b2e6e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b1b2e6e8fc0ed5d68803b3038b51e488ad596faf))
* **memory_alloc:** init memory_alloc ([e372469](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e3724690391e3bb0d5eca16ba60d0288ad9a2731))
* **memory_alloc:** per CPU rollback memory allocation ([074e627](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/074e627010c529552faffd546a8ec8a809c8d7d1))
* **misc:** ensure SP image is last entry in transfer list ([872ec89](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/872ec8910cbfcea5f5f340caa1c7e2db73d25ba9))
* **plat:** define memory alloc library ([f93e961](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f93e9615ec118bb6e2181c83af625feec9158058))
* **shrinkwrap:** add common base configuration for SPM TFTF tests ([d985168](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d985168f83772d85d8ac03633b4b7bc0cfa91cc4))
* **shrinkwrap:** add EL2 SPMC TFTF CI overlays ([9b87fad](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9b87fada6de6e9b8d74a55677cbdc4d34a943dfa))
* **shrinkwrap:** add Kokoro target to build Hafnium from remote sources ([f430e5b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f430e5b2feccc6b49db972a255b14ad02ffd2212))
* **vm:** extend vm state to aid live activation ([012ecfe](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/012ecfeb23c13d3cf15d59a0ea64d052b98ca5cd))


### Performance Improvements

* **ff-a:** remove redundant error handling from api_ffa_mem_perm_set ([85b8a5d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/85b8a5dc32ea22a138dd013b6069d7c5d4192e64))


### Bug Fixes

* **api_ffa_mem_send:** check header size before iterating receivers ([a9d6a31](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a9d6a31f7e48669aa32844a76df30041de830095))
* **api_ffa_mem_send:** fragment length check ([6828e3e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6828e3ee69f875fb7b7d698217d1b7a32dac3c7a))
* **api:** prevent buffer overflow ([6667313](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/66673139fa46e03fd99027064c6d41cab2e4a402))
* **build:** make GN formatting failures fatal in check-format ([486e00f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/486e00f48acd55a434ec2b58fecb0eb562582bcf))
* change error to warning when no tests match ([4740b2d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4740b2d4c9b7b11dcf1a5983793cc53a5445107a))
* defer freeing the memory used for old vCPU structures ([f242cb2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f242cb22c6850c5e1f0287b84fa43646eaa95280))
* **deps:** poetry readme.rst does not exist error ([3faec86](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3faec86de29e4cfda844140878e2cdaaa9aad72b))
* **ff-a:** carry forward non-RWX permissions in FFA_MEM_PERM_SET ([bb08d20](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bb08d20e2d4505fdd8b6af764224559c8cafe6a2))
* **ff-a:** check alignment on RXTX descriptor offsets ([b9c1912](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b9c1912cbe872d6e9cbeb0238569ddb88728e15c))
* **ff-a:** drop FFA_RXTX_MAP_32 from features ([aa100c1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/aa100c1b8ee636b1da4bb20d99af9dee436a1cdf))
* **ff-a:** relax constraints on FFA_MEM_PERM_SET to align with spec ([5c441ff](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5c441ffa7bbfa4e6a80cf66df7e178898f6f21dc))
* **ff-a:** version negotiation fails when preempted by S-interrupt ([1fff55d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1fff55d2923873239150c0aba0f88d8d5740af4d))
* **ffa_memory:** ff-a v1.1 incorrect struct size in composite offset ([95ccb5d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/95ccb5d19b2a2062cef89efb820adcb2c8410d27))
* **ffa_memory:** initialise mode and map_action on all exit paths ([d979abb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d979abb2643c4035ea46aafc0c82632b9959e9da))
* **ffa:** align ffa_feature handling and coverage ([7ae7d28](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7ae7d2817d17489e2982b47e5d3baecde5d9fad6))
* **hftest:** correct device range ([38b07b6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/38b07b6bca2857684e990765351fee630aeed890))
* **hftest:** fix memory_free return type mismatch ([37f2b83](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/37f2b83c5877dbf1c87a4b84af9ef77040ed3c20))
* **hftest:** fix OOBs in ffa_msg_send_direct_req2 ([0a3a396](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0a3a396cdc365179637ee2a9bd4dc791bd45e201))
* **hftest:** resolve -Wenum-compare for ffa_version calls ([96b765f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/96b765ffef7fba2600250b28ed853abd2a61741d))
* **interrupts:** clear managed exit flag on FFA_MSG_WAIT ([aa5fdab](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/aa5fdab99a75565a5b92ff6a4790857ee7a1baac))
* **interrupts:** correct interrupt bitmap size ([5290459](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5290459f7620d9bdaeda5b0b8bb800f122bb4ccf))
* **lifecycle:** skip boostrapping UP SP vCPU while hotplugging primary CPU ([cc8894a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cc8894aeae417e8de7f151ea7b0f637b3a8393ea))
* **manifest:** sanity check for exception-level ([b456768](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b456768404c854320d8a900fda1bc33f32bf9d5d))
* **manifest:** validate full memory containment ([76408cf](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/76408cfa35a7e0e60b03b5798eef89e63188eeff))
* **mem_share:** correct the fragment offset ([a283c02](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a283c0215a26a12e3759c447035d5c189ba7063e))
* **mem_share:** populate sender ID in FRAG_RX ([a334fe7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a334fe7e5f2b96d97b095002f60b6290b9763a09))
* **mem_share:** use v1.0 struct for region offset ([b446fd8](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b446fd897c14ae20dd309863d1c9fd7f46b5c584))
* **memory_alloc:** assert on accidental reinitialisation ([8e70c9d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8e70c9dea604d11fc5cce685d7f0bd6eb5a01fa3))
* **misc:** prevent dlog_buffer from being optimised out ([5c41b82](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5c41b8283edb3f44796b6e02de20f565f21e65d3))
* **mm:** check for security mode mismatch while handling fault ([3b2320a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3b2320a6acc29bb67d5c0c05d02cebf2a233d461))
* **mm:** incorrect level used to infer PTE during walk ([69f51f7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/69f51f762a688f30e3cef659c8b6facfc980fb57))
* **mm:** incorrect root level specified to mm_get_range_by_mode_level ([3e6c853](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3e6c85336db718a25f88f11d401fc75695f7e7ce))
* **mm:** remove assumptions about PTE structure ([96415d3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/96415d374ddc2bd8c26cbaddd8854fda9ba9b78b))
* perform explicit typecast to avoid sign conversion warnings ([8df91b5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8df91b58903022fb68e359d09745169fcfb84b52))
* **smmuv3:** use correct size for memory alloc ([f52cef1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f52cef18b179ad735a2efcdd43f6c18d8f637793))
* **smmuv3:** use incoming shareability for GBPA ([e2eff75](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e2eff756a53cba5383b3865f9f372c6d2365dc1a))
* **smmu:** version handling ([24c0aaa](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/24c0aaa11b76c52ae9acd75824810dd93f7e54e4))
* **static-checks:** address clang-tidy findings ([b330f58](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b330f580ae6cd9c3379311541c25d4fe354709c1))
* **static:** correct argument name in boot_flow APIs ([165750d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/165750dab19d89aa081b8c3c2eb385e7a66e89df))
* **test:** correct nested loop indices in unaligned page check ([e28aff5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e28aff5dbe9b777c2826c506a54e8ec5033b1289))
* trap ID_AA64ISAR2_EL1 for PAuth ([b18b13f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b18b13f1765252626b8d02ca0c60980db77a8c99))
* typo in ffa_func_name helper ([823ba51](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/823ba51675a38baa5fb569c8f258183bc0246060))
* **UT:** initialise memory allocator once per unit test run ([449330b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/449330b3464def0ec7ffad2e5060c4f20b32d0cb))


### Code Refactoring

* **api:** drop ppool argument from init func ([4716979](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4716979c7caeffbec39378d093bc04f19971e9d8))
* **api:** drop the 'struct mpool' use ([3a423f7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3a423f7b55273a6082667afe83b88ce828dbbe85))
* **arch_init:** drop the 'struct mpool' use ([147b2a1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/147b2a19417f5fd41170f3b1df22f84cc5c5099c))
* **arch/vm:** drop the 'struct mpool' use ([5359a0b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5359a0be4b38aed6283ba6066a750408e73d94d2))
* **boot_flow:** drop the ppool parameter ([2d6941e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2d6941e93c451702f13a0abbe1674ff5f978a6af))
* **commitlint:** switch to deterministic npm ci install ([e2e0ef3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e2e0ef3e87e8a6bc61baee855cbdfe9e8a8be5ba))
* drop 'memory_alloc_get_ppool' function ([59c25a1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/59c25a1e7e15dda14d78d2fa61c40f3e7546777e))
* **fdt_patch:** drop the 'struct mpool' use ([bde1f07](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bde1f07cfd5c09347a1377db8d5975910ddcae96))
* **fdt:** drop dependency to struct mpool ([dbb39d1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/dbb39d156a835014f310b1c37490f286fce88f80))
* **fdt:** drop the 'struct mpool' use ([bfec536](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bfec5360ac45a2cee016443d1579da2d0d9b68be))
* **ff-a:** drop the 'struct mpool' use ([14ff2ec](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/14ff2ecf8646514f88aa9767cb008611a759ac9a))
* **ff-a:** drop the 'struct mpool' use ([ee8bfa3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ee8bfa3ec066ba99a9320fb2cabc0fa5a31934d6))
* **ff-a:** drop the 'struct mpool' use ([fadb3f0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fadb3f0072c5ad2c265f1b09f4b75089e8a9dfa9))
* **ffa_memory:** drop the 'struct mpool' use ([61a8210](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/61a8210a16e84c42868617611c023771e75d919d))
* **ffa:** drop ppool argument from ff-a ([35a333c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/35a333c4447a4e674f6b576f2c519eaed13a1df3))
* **gicv3:** drop the 'struct mpool' use ([54c8adb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/54c8adb9ad1d60205edc5bdc70eb4173d176fa4f))
* **hftest:** adapt mm tests to ppool-less mm APIs ([40c135b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/40c135bae84a70f96e6f2089d5236ed09656088a))
* **hftest:** drop explicit casts for ffa_msg_send_direct_req2/resp2 ([80679fe](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/80679fe9bb59a491f5c03ed2ce09746a7a58b850))
* **hypervisor:** introduce SVC handler ([de0ad56](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/de0ad569b757d9450d455507ccb2ae93e65fa340))
* **init:** drop the 'struct mpool' use ([7f38863](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7f38863fc4d840203ee90ae241ab658072d9d455))
* **init:** drop the 'struct mpool' use ([92894fb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/92894fbca36c0f12afd1c41e43f0aac2bf5c1d29))
* **init:** use the memory_alloc ([bdfd46d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bdfd46dd52489fd9e3bc65c19eeba525a94ef178))
* **interrupts:** drop dependency to ppool ([de542d0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/de542d0d83b48405eaf7cbcae7e25c6738f0d23d))
* **iommu:** drop the 'struct mpool' use ([76e2a67](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/76e2a672b3004d86722bf2695d2496eb1a7872f6))
* **load:** drop dependency to ppool argument ([729fe0d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/729fe0d66576510addb6a9b3f9db0ed14ab1c508))
* **load:** drop the 'struct mpool' use ([0ae9f57](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0ae9f5789a55cee5221ec7528265742c9b5dd58d))
* make manifest service parsing common ([b331014](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b3310148e6a1d00329b173abfbdbb77f2a80a8d2))
* **manifest:** add services struct to VM and partition_manifest ([4d714d3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4d714d3f8adf90e7ce38e3f09ec04986cae60540))
* **manifest:** drop dependency to ppool ([50fab83](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/50fab83e97b48e1ed55c540864d8c8540b0569b5))
* **mem_share:** make share_state functions consistent ([a2fc3cb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a2fc3cb59b6ca951b960b1c925e9d4769d626416))
* **memory_alloc:** use check on the return of memory free ([d691eac](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d691eac95894ac45c7520cd041fbb1c78b17e1f7))
* **mm:** drop ppool argument ([e029ae0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e029ae0adbfe93186c4466ce118edb0f0feb04a6))
* **mm:** drop ppool argument from init ([35ef23a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/35ef23a14150df8e5636b39bcf1a60d7a75a9f4a))
* **mm:** use the memory_alloc/free functions ([3ea9f74](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3ea9f7480e64b7c8ba19830980babdb1824a63a3))
* **other_world:** drop the 'struct mpool' use ([a351bc8](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a351bc8ec7d009d0ede547fb8d2b4379a4b01093))
* **partition_pkg:** drop the 'struct mpool' use ([c73fa75](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c73fa75c3e1348dd493960c489a1eac7c70665cf))
* **pl011:** drop the 'struct mpool' use ([209b14e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/209b14ea0d115c47318b53d6ba075314204d1666))
* reduce code duplication in ffa_ns_res_info_get tests ([c45e612](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c45e6125a6b6c158ff7be3977ce6def33ef4e49c))
* **shrinkwrap:** clean up hafnium-tftf config and sources ([cf7df7f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cf7df7f99f4c55e099cdc2e043a3c6dcf8991c8c))
* **shrinkwrap:** move local development configs under configs/local ([ec4dbe9](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ec4dbe9d7caeb15a733f650481927c0bd52ddf34))
* **sp_pkg:** drop the 'struct mpool' use ([18356a0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/18356a0628ecb8fb2faab7a5b6fa5bb07a7156d6))
* **static-checks:** fail static-checks on clang-tidy errors ([8836e27](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8836e2733049b443e7a6e70c01d945652af73dc6))
* **UT:** drop the 'struct mpool' use ([9e530ea](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9e530ea5df65a1e893c719ccccc8d806caa8c15f))
* **vm:** drop the 'struct mpool' use ([24a9062](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/24a9062f10fd2724bd90a4968932b6560abf60e8))


### Tests & Framework

* extend test scenario to abort and restart SP twice ([b5e960e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b5e960e3df388392b54f7c5aff2a7e83ea0577e1))
* **ff-a:** add v1.3 partition_info_get image-UUID coverage ([baa543f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/baa543f1a6fa3892c729244216d528224a873ac1))
* **ff-a:** add v1.3 partition_info_get protocol-UUID coverage ([b023cab](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b023cab8058be2d9e3bd66d222513c6365e2cb8a))
* **ff-a:** validate v1.3 partition_info_get for NULL UUID ([5fb78cb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5fb78cb647fa3a023be5999d9ee50c005970f570))
* ffa_ns_res_info_get - add hypervisor rx/tx amds ([3bbe8ef](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3bbe8efa10e717ca8f79ca83f40f9eb0e8143fc6))
* ffa_ns_res_info_get - donate info ([9d75e27](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9d75e273004be5369a2854d2a805c24bc2e37a29))
* ffa_ns_res_info_get - donate info sel0 ([f19d9b9](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f19d9b961f040480cdd5f07b51e735750ece5482))
* ffa_ns_res_info_get - lend diff permissions ([77e6196](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/77e619699189c931b44d8278d13a2840ccd772a2))
* ffa_ns_res_info_get - share info ([b2d72e2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b2d72e280831ac3ee8c8e32c4f8bf33469deb866))
* **ffa:** test for multiple messaging methods ([5483e96](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5483e96c95f94d893f7f996002274619f66e60e4))
* **hftest:** allow hftest driver to pick the variant of BL31 binary ([9fa8457](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9fa845741072b1bf4cdec419cf0237b91ca6199d))
* **hftest:** build SPs with live activation support ([c6c9349](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c6c9349cf3eb01f6744ed06ca688b84cf4f979ed))
* **hftest:** emulate firmware store in hftest framework ([5d8fadb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5d8fadbe123a959e9d8a485959545e0865f138b2))
* **hftest:** prepare test setup to exercise SP live activation ([e1115a3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e1115a37c7892df995d29e64b1dacfa539986fd2))
* **hftest:** support to load partition packages at specified staging address ([3216d61](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3216d6158c4315e809c9c781130115f7f83cb764))
* **kokoro:** extend hftest `--debug` flag to `kokoro/test` scripts ([7cac879](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7cac879e2bff897d30effedb6285e3c739e84259))
* **lfa:** add helper utilities to exercise live activation ([fade589](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fade589fd9ddcea011fafc94c66d0277715b7d70))
* **lfa:** add partition manifests for live activatable SPs ([475f2d2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/475f2d21c14c16fd5c98af0dca15d2e972a26dd7))
* **lfa:** add robust checks to SP live activation scenario ([eebaef5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/eebaef5476ac74a43a625417ff01f87ce0c04f59))
* **lfa:** ensure shared memory is preserved across live activation ([a87cf83](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a87cf839e37bc8fdedd56ca632c43e593694b28e))
* **lfa:** exercise LFA handling when SP fails during live activation ([bd1d24e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/bd1d24eaef28f047ed4bcaa42edf7792604ff2d6))
* **lfa:** helpers to mimic saving and restoring from live buffer ([644af9f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/644af9fd51eac753bfd88d9d616efbfb6eb3336b))
* **lfa:** introduce fictitious live state structure and utilities ([8b1f4c6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8b1f4c6aaf94e822ccf021707eb25c62e126bdc8))
* **lfa:** introduce lfa client utilities for test driver ([92205e3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/92205e3a41e5df3fe883a89f03b596d022c29922))
* **lfa:** make SP live activation fail while handling stop request ([887614e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/887614e22c4af23b6cfa11226e35a189970ec29b))
* **lfa:** prepare SPs to receive live activation status hint from SPMC ([ed79678](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ed79678c7166459bbd96bd595ba6cc0f410833f7))
* **lfa:** simple scenario of live activating UP SP ([10c7b88](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/10c7b88e6847001128d44651dbb30c034cd091b8))
* **lfa:** support partition stop request for live activation ([a258fae](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a258faedea261966d2c3b17999be3fcda429a8e3))
* **lfa:** support to dynamically locate live state buffer ([aec5f51](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/aec5f51627948d80f0ab57e5ed473d411401f57a))
* **manifest:** add image regions to boot params ([77b7e47](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/77b7e470f4ff2331e741acd9d5f89ea0a766913d))
* **manifest:** add unit tests for canonical image uuid support ([3a04ce9](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3a04ce9bb7ece17230140b0670a548d2673e9ab8))
* **manifest:** split properties and children in ManifestDtBuilder ([cf56010](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cf560108023818f417514c2afbc2e96a076ae338))
* **manifest:** update partitions to use v1.1 ffa manifest ([3ad0c9d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3ad0c9dce843e4e83e9fc021a440ea6e46002f37))
* **manifest:** update tests to v1.1 manifest ([281c275](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/281c275a8c9f8c9be5e1d12251e2980dfbd25974))
* **manifest:** update UUID tests to v1.1 manifest ([4c0425b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4c0425b6cd43d2819bf453952f69db45755d8064))
* **manifest:** validate memory regions invalid ([b664a7b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b664a7b235a1bdca4763296aafa9bc414d3563da))
* **mem_share:** optimize FRAG_TX test path ([e6d28ed](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e6d28ed7e7a949f02c7f1ff0bc06c6fb008c458e))
* **mm:** remove double mm_vm_fini in mm.map_reverse_range_rounded_quirk ([c0f002d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c0f002d6eff5225d9fde6883f3fc61baa3a03f2c))
* **shrinkwrap:** add generic test group runner script ([75cef40](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/75cef40c43e3c541a99358d3674d617e5c1b9cbd))


### Build & CI

* **commitlint:** add scopes for submodules ([e263990](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e26399063743eb75827437195eb6e79fa6c04ba1))
* **commitlint:** add smmuv3 to commit scopes ([dadb2b5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/dadb2b534e64d1a4bd307eb2893ff13ad1aa9a29))
* **commitlint:** enforce scopes for commits ([003f08f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/003f08f359300b95b74cf1fbf32ba5b2cd18597e))
* **commitlint:** restrict commit scopes to approved list ([867c5fa](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/867c5fafe6d37e3768b0a0a56bed666bab5b7ca5))
* **deps:** add NVM version file ([cd6a408](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cd6a40889a5ec093be943e227fceeedd84d60e75))
* **shrinkwrap:** update shrinkwrap submodule to 2026.3.0 ([d2127a2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d2127a20a36ebd639e7202d65987d986159c7a71))


### Documentation

* document PDF build dependencies and instructions ([395ec24](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/395ec243334275e51bac1650c5dea8173c21c0be))
* **fvp:** document FVP model version used in CI and testing ([22601ac](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/22601accbdadbbe54af6ee90f97e3ebb11ca3031))
* **lfa:** describe support for SP live activation ([97c7605](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/97c76057e571378e32341731fc194c271388aecf))
* update maintainers list ([66d5e05](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/66d5e0530c2951877b09565a35196695b5c8d881))


### Maintenance & Chores

* **build:** sort unit_tests sources in src/BUILD.gn ([e946721](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e9467212460babc23d3d23a19551cd5ac3b1661d))
* **deps:** track poetry lockfile ([ae4ebbe](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ae4ebbecaea05710aceee547c22faffcf9766bac))
* drop api_init function ([18e7546](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/18e7546299f6f25014a177ea08e9f36b56c196b4))
* **image:** clarify --package usage in generate_partitions_json ([1164b8a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1164b8a78489a16f50b513f88735df2a983ce977))
* **manifest:** remove unused manifest_deinit path ([19b0feb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/19b0feb7ebe8d1904932a807ee9db8ea59e07cab))
* **misc:** clean up initrd boot remnants ([6ac92bd](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6ac92bd3089cbcf6594666bc07dbad4ba571ff7e))
* **misc:** miscellaneous fixes ([ae51c7a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ae51c7a2e4c56671ed7692d319d09b5ad48d3185))
* **misc:** small fixes and improvements related to lfa ([91abca4](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/91abca469dfc0f153b22c59b9d237be094d62477))
* **prebuilts:** new BL31 binary with Live activation support ([c2cf649](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c2cf649d0d36f2f9b6300019797f11998d14b6a2))
* **reference:** update submodule for unit test toolchain changes ([d1a2dbd](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d1a2dbd95beaabc7495fcef07b1c2ad9707dbf50))
* **reference:** update submodule to fix format changes ([28dfffd](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/28dfffdf24cc853f6878fd8f0ec636ac69a959b3))
* remove ffa_memory_return_delayed service ([86bfa18](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/86bfa187aee25bda4c5898487cf6c789d40eeee1))
* remove/move unnecessary headers ([5e48e4b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5e48e4b6333df11710cedaefe7eb4ee35c6eef1d))
* set clang-format PointerAlignment to Right ([7fe7d67](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7fe7d67cffa475c1cafe42263e34fb60adc04d86))
* **submodule:** update reference to include UART base address changes ([f9ecd21](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f9ecd218bc157f35c644bcc8e483f20a4bafb7d1))
* **tl:** identify final TL entry when image binary is expected ([ae9e92e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ae9e92e0f2bed3d4e0142e3b5f7140c19bb1579a))
* update googletest submodule ([0deaa9f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0deaa9f7067df1665ba34b3ce416d91c10140f9f))


### Code Style

* **misc:** format for *.hh files ([aec094e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/aec094ea3feabac648b7b70ce861471b2a1b4fe1))

## [2.14.0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/refs/tags/v2.13.0..refs/tags/v2.14.0) (2025-11-13)

### Highlights

* FF-A v1.3 Enablement:
    * Bumped Hafnium FF-A version to v1.3.
    * Support for `FFA_NS_RES_INFO_GET` ABI which allows NWd client to discover
      the non-secure resources accessible to Secure Partitions.
    * Refined the notification model to support only global notifications, removing per-vCPU
      flag handling for clarity and compliance.

* Partition Lifecycle management:
    * Support for newly added lifecycle states and transitions for Secure Partitions.
    * Implemented abort handling in cases where a Secure Partition encounters a fatal error.
    * Allow Secure Partitions to abort execution using FFA_ABORT ABI as well as
      specify actions in response to abort.

* Interrupt Controller Enhancements
    * Added multi-GIC configuration support for complex topologies.
    * Strengthened validation to detect and prevent SPI range overlaps.

* Shrinkwrap Test Framework Integration
    * Integrated Shrinkwrap as a third-party test framework with static YAML configurations and a
      flexible runtime overlay manager.
    * Modularized test drivers and added developer-friendly CLI logging controls and reliability improvements.

* Build & CI Improvements
    * Upgraded developer Docker image with toolchain, Shrinkwrap, commitlint, and doc-build support.

### Features

* abort vCPU upon encountering fatal exceptions ([4b544f6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4b544f6ebb5d617dffcc9c3f637aa078bf3f857a))
* adapt vcpu operational mode to interpret newly added states ([98ab38b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/98ab38b51a861c44c89053ee457ad41a3189f20a))
* add support for newly added lifecycle states of a vCPU ([d6c055d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d6c055dd5283b4e394b3ea7434f35522fb25fab8))
* add support for partition lifecycle support fields ([c35573d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c35573d1afc608d0beac519ab0b103fc4f9d7ab6))
* add warm boot power management message handling ([7dae040](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7dae040b77d79522d1785621a0a6f2d3a9f5a660))
* allow FFA_ABORT ABI for all partition runtime models ([a34e6a1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a34e6a1661a9d7b816294432aefc41724bf05084))
* **api:** api handling for ffa_ns_res_info_get ([a5e0a6a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a5e0a6a09e23729254198a0e24c21281d86eef02))
* **api:** ffa features update for ffa_ns_res_info_get ([0c5a19b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0c5a19b658b3625f01fae0132fefd6e0f91fbe61))
* check if a partition is discoverable during its lifetime ([6cb80be](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6cb80be14a9c0b8120f85e00229737421d0535a0))
* **commitlint:** commitlint docker functionality ([207c3c8](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/207c3c897db57fd2c676df93160d8b8988d09c4f))
* **docker:** add Shrinkwrap dependencies ([defe5ce](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/defe5ce80e0bcab5e6ab7518f5fc87d912eeae6b))
* **docker:** update LLVM toolchain to v20 ([2a1ccc2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2a1ccc2e06b2112eb745d80c38b94ada40df1769))
* **ff-a:** ff-a header changes for ffa_ns_res_info_get ([96fad47](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/96fad47337fd26502dff4eebeb866dfefd3a14d7))
* **ff-a:** forwarding for ffa_ns_res_info_get ([04e353d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/04e353d431552a920d01f64cdb1b4082b538bbdc))
* **ff-a:** share states non-secure memory reporting ([96bed7c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/96bed7c759863cde63117bb5004f0f7c27ef6aa3))
* **ff-a:** state reset for ffa_ns_res_info_get ([847c9cb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/847c9cb3754b2da3ebf155b900b402a41faf611c))
* **ffa_version:** bump version to FF-A v1.3 ([6caa668](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6caa668e1ed259d2048e1a9cb4766266f191336d))
* **ffa:** advertise per-vCPU notifications unsupported ([3624dee](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3624dee81771af3d7c91092e922e19a2a98c9a16))
* **ffa:** disallow per-vCPU notification flags in BIND/SET ([d4065ce](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d4065ce2c742db6b1bf3e90adcac887c44b28bc1))
* free any resources allocated to an aborted partition ([d88b014](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d88b0146af9f7cabc836437c97c47d844d1b2ca5))
* **gic:** enable multi GIC support ([5d7c565](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5d7c565fc3e103a02fcfce2105c2320af02af28e))
* **gic:** update SPI range overlap check ([6b63598](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6b635982916fec385477e3b322684999cf44a41f))
* helper to reset and free partition notification bindings ([cbb836c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cbb836c5ed86b0d083e3f26ea21191c4b4b3d8d6))
* helpers to free page tables associated with a partition ([f7d5af4](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f7d5af457ac5cfc5dae5cf1cdb494e25aa6a82e8))
* helpers to reload and reinitialize an FF-A partition ([8e5d51a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8e5d51a8ec72746fcd89ed49719276c5b7f0a1fb))
* **hftest:** add click subcommand functionality ([c913c5b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c913c5ba0d9e34e634534107c13f0ae2790c7900))
* **hftest:** log resolved FVP command from shrinkwrap ([fb0c393](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fb0c393f59fba5d21594384853b4d50161959e53))
* **hftest:** support global logging control via CLI and environment ([cd3b428](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cd3b42817cd6041a959a8cace041f3be9ff0c477))
* implement state machine for vCPU state transitions ([199a3b1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/199a3b1ef8fd1695ce4ea5eb83d9ee9a0db9ddeb))
* implement state machine for vm state transitions ([84259c9](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/84259c9272aa9a23d4df804ccf00dfeff076396b))
* initial support for FFA_ABORT ABI to abort partition ([04cf9e8](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/04cf9e8185c8120867d601a7a2758871649f47a3))
* **memory_protect:** add function to check support ([c234c5b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c234c5b2bc06d47367dd74e415142b429d47588d))
* **mm:** page table range reporting based on mode ([d59633a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d59633aa69f82bfac0772a07106445f3f0bc60a4))
* **prebuilts:** bump TF-A SPMD version to FF-A v1.3 ([a1afc03](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a1afc037c5c8fb1f37865b346e302b4ef94705a9))
* prepare to restart a partition with its manifest ([1fb86ac](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1fb86ace51a38b1e39cf31e0383b2c7e123cdc0f))
* put aborted vCPU in appropriate state based on abort action ([9409306](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9409306e925c3a6e092f2e3ac7e65999c2955277))
* reclaim memory regions of aborting VM ([b902a4d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b902a4d674525e37ec21ef1b31f02011987e2052))
* relinquish memory regions of aborting VM ([2da53c7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2da53c70af448086ce05fa4d2126d02e5606b7c4))
* resume halted vCPU after target vCPU reinitializes itself ([3d1456b](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3d1456b5d45d51d8c10ecca4eaa96ee3e927f7bc))
* **shrinkwrap:** add API for runtime overlay configuration ([14f86d2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/14f86d27331d4f1fa875611da9aeb0f549ead774))
* **shrinkwrap:** add developer-oriented configs for Hafnium-TFTF test ([5babb77](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5babb779dff05b3ce35abf856a7a68bf13d66713))
* **shrinkwrap:** add shrinkwrap as a third_party submodule ([24adcc0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/24adcc0213511dec3942531b0e7f012d81576779))
* **shrinkwrap:** add ShrinkwrapManager utility module ([1a6e19a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1a6e19a03a694ba767714d5e8ab5019d0263f32f))
* **shrinkwrap:** add static YAML configs for Hafnium test drivers ([e190ef3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e190ef3a84ff56ad7859bd9f1685ad7b445da81f))
* **shrinkwrap:** integrate static & dynamic overlays in test execution ([969f321](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/969f321eec1d6c27ace5e0a14d872fead84f13db))
* support for restart abort action ([e7400ac](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e7400ac2a218aefdb179ea7bdd51ffd2a612bf96))
* take action when vCPU aborts while in SPMC schedule mode ([9799a3a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9799a3a3d9830c849242e9b11970cedc1064d0a8))
* take action when vCPU aborts while initializing itself ([130cbdc](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/130cbdc64041d7f8d11c1f8323761bf037aed998))
* take action when vCPU aborts while processing a message ([7e7847c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7e7847c933d0c0a2011e694339c87d20f4827134))
* update to `-std=c23` ([1564bcb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1564bcb7505ea01ca70a16d2980c61e3ed0f16ae))
* update to c++20 ([34cd6a7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/34cd6a7cf0b9a79243511367630ba206b0fcb2f4))
* vm state transitions based on lifecycle guidance ([e624cb1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e624cb1172dfd6f638c00e695faf8e71b7feccde))
* **vm:** normal world vm rx/tx buffer reporting ([06e3a6f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/06e3a6f1a8528169a5ac5356f02c61c5e65bcf30))
* **vm:** vm abstraction for ffa_ns_res_info_get ([0715935](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/07159354dfaf5919fb629cbc94d7f6cbb110d4d2))


### Bug Fixes

* 'map_action' was set but not used ([305bfe7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/305bfe7a752a0cadb31bb21f790f7094dd34e0c6))
* check if regs are available before migrating vCPU ([d90e4b0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d90e4b080014cdd362bf03592535593659657ecb))
* **config:** restore correct EL3 payload binary path ([14232c3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/14232c31f7d8968fb33a4ca7e55eb20060535de7))
* **docker:** ensure PLATFORM is forwarded correctly in Docker build ([2435318](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2435318731c960be1dfdcf84accbf1f357d93665))
* **docker:** env var HAFNIUM_FVP mounted ([16000be](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/16000be8d1e33b8c30ff33fdd86126f0ed95cbbd))
* **docs:** documentation build errors ([f790d8d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f790d8d3e9540104fa3ab42238d4d414eac1e12e))
* dont initialize page tables for IOMMU twice ([9f06689](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9f06689c070af10c1e0f0679942a019207fe2d67))
* **ffa_memory:** avoid changing receiver's permissions ([e89c793](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e89c793ac103f8fec9d40001f6383e3e450c00a6))
* **ffa_memory:** prevent X permissions on NS memory ([13e224e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/13e224e36da64f47c327df8f8552e67bf7434aff))
* **ffa_memory:** retrieve response with correct permissions ([c57709a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c57709a63a102dc54242b274c07b5d74b9e5cfb4))
* hftest return error code on failure ([ea9a8ea](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ea9a8eafec0958c6c8d1c3dad86a71772d159204))
* **hftest:** correct hf_out variable typo ([ca63a67](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ca63a6720cef623af43723a1140eb1dd7f430434))
* initialise composite for v1.0 descriptors ([b484b7d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b484b7d412023218ad8282113e0e1d68a1ea9026))
* **ipi:** fix deadlock in IPI handler ([aa32dec](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/aa32decc504391e3d78b4b4bb01fb576923f0fa6))
* **kokoro:** avoid duplicate assert-enabled run ([4ad40ef](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4ad40ef92a786dd538cc2712449b93dfbee48348))
* **lifecycle:** relax the check for vcpu state in SP_INIT runtime model ([9dd9762](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9dd976252b14728ce84989fd49b722f971e375f4))
* negotiate FF-A version before other ABI invocations ([4b6d88d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4b6d88d594bfa08582fc3d860372852c74490f72))
* relax receivers offset check ([6800700](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6800700395a0cf7dda5d9871ac4daef242de904e))
* remove `static_assert` macro ([6e08343](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6e083432871caebfdb3958dbded52a33bc6a8cc4))
* **shrinkwrap:** streamline debug and coverage overlay handling ([5e71823](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5e718236afd678c2be13bd74af49137cd0bf0f68))
* **smccc:** use full GP regs set on physical FF-A instance ([e8015b4](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e8015b42cf3aa87f61849a2bbfb7a65710c01d2d))
* **static checks:** clang-format failed with previous change ([c0c0940](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c0c0940775327c102dbc84c715a32e3068bd5e60))


### Code Refactoring

* `__typeof__` to `typeof` ([33e7709](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/33e7709756ba8847c6eea33f08203021d796501e))
* add explicit underlying types to enums ([0dba87e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0dba87e2df595794af063de72db3adf46d28e1a7))
* align python3 management with hafnium CI ([581e54a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/581e54a7af547ff1c691774520042b7968e76277))
* create helper to unmap rxtx buffer pair of a partition ([507c997](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/507c9974403c9a8ae1bc53eee606442e53477286))
* **docker:** drop Dockerfile.local ([108b045](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/108b04504d3b742332348ae51d7d92c1e02e7f85))
* **ffa_memory:** tidy function to init retrieve response ([59e6bc7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/59e6bc72907d771ba112f060bc424882114729b0))
* **hftest:** modularize driver classes into separate files ([5f96339](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5f963392921aeb79b633779035208f4824d77d66))
* **hftest:** streamline FVP drivers with static overlay key mapping ([610c692](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/610c69238ef898e7f1355ecb82fa49550d080255))
* introduce sp_wait helper for use in test services ([efd1343](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/efd13435e1c6405b8ff973106e4ec770425324cd))
* remove `static_assert.h` ([b9afc89](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b9afc8975ddbd98bdcd3507199a0521bd6f94843))
* remove `stdnoreturn.h` includes ([1923faf](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1923faf1c9d9d08067c3684934e58f2b904a346d))
* remove unnecessary includes ([2267efc](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2267efc0323b25ffc8636f73ffdcc387aab2b3fa))
* rename helpers for legacy abort behavior ([b8fa4c1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b8fa4c143fa856c05e4f7a5ce6764cd8c5f0d98f))
* simplify hftest test registration ([95d5c06](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/95d5c06c8b7b976db50cd06a425f7c2f07db26fc))
* use an enum for FF-A function IDs ([adf6daf](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/adf6daf5daf568c0ac31646d2aca2b1528e32602))
* use C23 attribute syntax ([f42eaf3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f42eaf3df1722abc437ba25c8f61fda8af6b96a2))
* **vm:** drop vCPU args from `vm_notifications_state_info_get` api ([6b3b546](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6b3b546184ad9362b0210878465a0ffef57db2c0))
* **vm:** inline bindings init with single loop ([0049286](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0049286afba39dd38ccc886dc85198481b674772))
* **vm:** remove dead per-vCPU notification fields ([ed2205a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ed2205afe4e77d33bf73a0fda0de1c7fa5de94b1))
* **vm:** remove per-vCPU notification init and allocation ([10208d0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/10208d04a4c9aa6403bc6ffb1c9ad2911f3e1c37))
* **vm:** remove per-vCPU state and simplify notification helpers ([a14c139](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a14c139865db18cdc6f579233b6fde1e56fac331))
* warn against implicit fallthrough ([402b1fe](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/402b1fef34f7b6737f690a96d7484cced63e33cf))


### Tests & Framework

* add checks to make lend_elsewhere_after_return robust ([935ec41](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/935ec419b18107137dc87327bbb4b37b3e35fcde))
* allow partition to signal initialization fail using FFA_ABORT ([6d116e0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/6d116e053ec1df8c83313daff1696b56bcf01361))
* call functions for ffa_ns_res_info_get ([f2cf2c0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f2cf2c0fe0b096fa3752da6a0b5a7f3c0964c3e3))
* **cpus:** serialize the logging to avoid concurrent stdout access ([53173df](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/53173dfc5518695a899cd118d845ba0653ef30da))
* **ffa_memory:** use NX with NS memory ([5b737ee](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5b737ee53d64a0499d6057fb67dea2531c89fffd))
* ffa_ns_res_info_get - ffa_features ([3a61f8a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3a61f8afacf5da3aeaf9a81a186b9ef986d65ac5))
* ffa_ns_res_info_get - get all sp info ([01381b9](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/01381b999dfa17842301e279d78c97d70a00ca3b))
* ffa_ns_res_info_get - get all sp info s-el0 ([9c11c2e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9c11c2ed795c5a9f330155ec625c0f63df67a8ac))
* ffa_ns_res_info_get - get specific sp info ([13d0d24](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/13d0d2402b1eb5cc0d6a1da9b00bede5d3e950d7))
* ffa_ns_res_info_get - invalid calls ([84c58cd](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/84c58cda077e6a7a281a30ceffb7004565f57209))
* ffa_ns_res_info_get - lend info ([5966975](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/5966975c4df9023564b1c74a3a65e87a0725fa95))
* ffa_ns_res_info_get - lend info s-el0 ([4ef0270](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4ef0270debcf32cfe41993ddf968bbcc1e173993))
* ffa_ns_res_info_get - lend multi permissions ([c10983a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c10983aca83bf1f0401f2896dc48608bd490892d))
* ffa_ns_res_info_get - lend multi receiver ([532670d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/532670dccf1581a2cdc160099d89f686f015cf13))
* ffa_ns_res_info_get - multiple calls ([b671e7f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b671e7f2706370402af47c6aac82dbf749330f0d))
* **ffa:** add FFA_FEATURE_NOTIFICATION feature discovery check ([0ced066](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0ced0662ea1cff9098dc8f42c3bd633ce687d57c))
* fix scenario incorrectly assuming lent access ([621393e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/621393ec0adee4c3d69264a887ca4d634a00b68d))
* introduce new setup to exercise lifecycle management ([817eda0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/817eda05d6df8723c21ec6df167bae2e6d8c1b0e))
* manifest updates for ffa_ns_res_info_get ([29d8542](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/29d85422324a86e4c006de1e95dae5582546ca61))
* **notification:** remove per-vCPU notification test coverage ([630f862](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/630f862c4edb5010a43943159c6bb9700c188377))
* precondition updates for ffa_ns_res_info_get ([4fcf334](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/4fcf334e31e0f5a0a5c4104ee42cd50b5f710170))
* secure partition aborts direct request from another SP ([c9884d5](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c9884d5d1fd404399e7507cc4f5d7154a79668c5))
* secure partition aborts direct request from NWd ([cccaede](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cccaede805898df491c56feae2c5a776a2f61b45))
* secure partition aborts direct request in SPMC schedule mode ([7ad6133](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7ad613367721ba4b33c78f23ae381bb491788e60))
* secure partition aborts during indirect message processing ([e99580e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e99580e46099468fc2a895c86c369cd06a4d9266))
* secure partition aborts upon a fatal synchronous exception ([e56d53d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e56d53d5f53362245621f7d1b26146f92fe928c1))
* secure partition aborts while handling secure interrupt ([721ad8c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/721ad8c92c4571e471424c73288e3a9c415bcca8))
* secure partition preempts sp and aborts while handling interrupt ([abefb61](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/abefb61b1cc0f142654472b379bdb5b181d90b52))
* sel0 restarts after aborting voluntarily ([cf5640f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/cf5640fd701c1a0bd3c2a53efee5cd40daef05d7))
* sel1 partition restarts after aborting voluntarily ([2b61eb7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2b61eb757f5b640aa09157c4be1aecead8978c62))
* service updates for ffa_ns_res_info_get ([7525b26](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/7525b26617bae944b4664f14922c091cd3e8053b))
* spmc can reclaim memory owned by an aborting partition ([9b52b18](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/9b52b18c7579e4a55d544fe467e8d9f4ec539508))
* spmc can relinquish memory on behalf of aborting partition ([e3c3a4c](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e3c3a4cfda49bccf16ec3fdb216616841e104fc8))
* the FFA_ABORT interface supported only at SWd instances ([ea83218](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ea83218ebe36a8e2f69be5c31c29447e22d65787))
* unit tests for parsing lifecycle support fields ([08df7a2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/08df7a2d325e6f254e51ffdb14b7424e4ad30e9c))
* **vmapi:** drop redundant tail check in SP interrupt routing test ([0b6e0b3](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0b6e0b3e759f2bafc8d83e36162106bfaffd261f))


### Build & CI

* **docker:** add GNU Arm toolchains for AArch64 builds ([a589bb4](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a589bb404ba1f339356d174b3869b770d1dc1c2c))
* **docker:** add Poetry support for Shrinkwrap workflows ([8a6d138](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8a6d13805f262eee50adefc8b832d80672addeba))
* **docker:** add safe UID/GID user creation for hafnium container ([f202093](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/f202093837d2f35beab07d8a657c57f4c283df26))
* **docker:** add Shrinkwrap environment setup to container entrypoint ([24f286f](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/24f286f4f542947891f73923ff971d7b02c5042f))
* **dockerfile:** add click pip install ([eef3dbb](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/eef3dbb23f2e3ae7e0341b131c947e0939febfc2))
* **docker:** install PlantUML/Graphviz and bootstrap Poetry docs deps ([c966185](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/c9661856157f639682d66582171a74312f135a73))
* **docker:** mount TF-A & TF-A-Tests directories for Shrinkwrap builds ([82ba745](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/82ba7452685c9c5304f687466fca5f9a5efc0f07))
* **hftest:** modularize test targets into kokoro.mk ([eb9c655](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/eb9c655664173b5a5719201e184ef290357d3c70))
* improve FVP binary path detection ([ca2872d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/ca2872d1f504f4a397845fa128e3685a653afc94))
* **kokoro.mk:** support local TF-A/TFTF build via Shrinkwrap ([0ece517](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0ece517f71e1678ff2f8f36b58fb6ab9c8069c61))
* **kokoro:** add Shrinkwrap test targets for hafnium-tftf integration ([2c10cc6](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/2c10cc67d065850342a4db6ec94497968a8d42dc))
* **kokoro:** make build.sh the single test entrypoint ([0d8da00](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/0d8da00a698ebc35a5940d33832c3b19bfbc3ee4))
* **kokoro:** split unit and QEMU tests ([b5ae087](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/b5ae087f5d243855c756e4c22f263501dd20ab12))
* **npm:** add changelog generation dependencies ([263f282](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/263f2823ea0de04c01f37ab7c51e001f07f20037))
* **npm:** add release script and changelog configuration ([a6c58c8](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a6c58c8b1ebeb7b3401d8d49bd737d17920c90ec))
* **npm:** include version metadata for commit-and-tag-version ([e8f3e6a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e8f3e6a1fbc01b8c7f77d7e476bdb492e25c78af))


### Documentation

* add troubleshooting note for cleaning up build artifacts ([02a3393](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/02a3393ba66a0b1a9c8dae20aa06d7b91b133aaa))
* **commitlint:** add setup and usage instructions ([660bdcc](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/660bdcc8ba843c31333adc7d8841ed5aa6056044))
* **hftest:** add Shrinkwrap-based testing guide for Hafnium ([13ee0e0](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/13ee0e0c09ff07147fc6e9f169ba5f1a640885d5))
* **notifications:** state global-only support, remove per-vCPU ([a3769bf](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/a3769bfad948026e7a22f6d1a303f0cc96a89fbd))
* **prerequisites:** add system and Python dependencies for Shrinkwrap ([fd2f846](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fd2f84660a7e252b7a898ce79f89154cbfce1549))
* **prerequisites:** click install instructions ([08f89d7](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/08f89d7b62c71251e2537bdb652138ccd290f347))
* secure interrupt handling policy ([3d1c2f1](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3d1c2f128501fd324955b60fa28eccd4e3b179dd))
* **spmc:** describe partition lifecycle support ([98ed638](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/98ed6384b00e9f12068f3b203b316b07200455a2))
* **spm:** fix reST note directives to unblock docs build ([33c7930](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/33c79303cbf14d6dd9946677d2b50b9779eaee05))
* threat model update for SP Lifecycle support ([50c67de](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/50c67de110ae7960bfdc0decaddfe5b62daca7c9))
* update `prerequisites` ([3678f20](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/3678f2044b547341d3952d1f090b895c0fb98075))


### Maintenance & Chores

* add *__pycache__* to the .gitignore ([481fda2](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/481fda23765617ca6333797216e5207e07344254))
* apply clang-format ([00dbf3d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/00dbf3d2cbde895df40d3e9f0b38851cd68a1292))
* **ci:** drop "is_kokoro_build" helper func from test_scripts ([808e60a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/808e60af3befb14b9d614e1327dc17b468f6b071))
* **commitlint:** set up commitlint config ([12f8242](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/12f8242ca94c9dc6e39b1ea679d1f2e8eef803b8))
* **ffa_memory:** doc comments and variable renaming ([87b838a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/87b838a02d0aa99e46a45684d8c1904bab93e8fb))
* fix clang-tidy warnings ([d0123af](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d0123afc1f89665837c8cd20445caeab9503343f))
* fix miscellaneous issues ([8689101](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8689101a2faec51f85003b818198a965d5fe3231))
* fix new clang-tidy warnings ([989707d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/989707d433647945b545d7b0fbf5ac3494eea1aa))
* fix new warnings ([e8d7c16](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e8d7c1600edc321b842a9c7a49e401b0aa6886a4))
* **gitignore:** ignore node_modules directory ([e289d9d](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/e289d9d86bc99862b1bcda66f33151fb6194d293))
* ignore vscode files ([1cedd5a](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1cedd5a50b33382ce65764170aea5d5a832e2310))
* logs lowered in verbosity ([40e14ab](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/40e14ab93e04bfb98ca9f0a52344c7c3335ca3a5))
* **makefile:** add commitlint rule ([d6da8ef](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/d6da8ef98a77b082adb80b4a0243e123000e4996))
* missing static in function definition ([8966c95](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/8966c958a45fbae94126a636db98a0ca4d823304))
* **static checks:** correct make command text ([fb68dae](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/fb68dae1fa701feb017929883f6358b039e7d179))
* temporarily skip failing test ([1856d3e](https://review.trustedfirmware.org/plugins/gitiles/hafnium/hafnium/+/1856d3e2c9dd6ad4ac7ef19a574b19131815aec8))

## v2.13
### Highlights

* FF-A v1.3 (early adoption):
    * The `FFA_MEM_PERM_GET` ABI was changed to return permissions over a range of pages. If the range
      has varying permissions, it returns the last address to which the same permissions apply.

* FF-A v1.2:
    * Added support for the `FFA_MSG_SEND2` ABI to send indirect messages specifying a service UUID.

* Runtime Support:
    * Secure Partition Package format using a Transfer List, following the Firmware Hand-Off
      specification:
        * Transfer List library was added to the codebase.
        * The legacy SP package format and TL are differentiated using a `magic` value.
        * Unpacks the SP manifest and retrieves the SP binary from the TL.
    * Passing the HOB structure to SP as boot information:
        * TL package format leveraged to convey a HOB-like structure to the SPMC as part of the
          corresponding SP package.
        * FF-A boot information protocol used to propagate the HOB reference to the SP.
    * Added ability to trigger SRI when handling an interrupt for an SP in a waiting state:
        * New `sri-interrupts-policy` configuration in the SP manifest initiates this behavior.
        * SPs are included in the return of `FFA_NOTIFICATION_INFO_GET` if they are in a waiting
          state, have pending interrupts, and have configured the `sri-interrupts-policy` field.
    * Allowed use of `HF_INTERRUPT_SEND_IPI` with the ID of the calling vCPU.
    * Bootstrapped all secondary vCPUs from all MP SPs when bringing up secondary cores.
    * Deprecated subscriptions to CPU power-on events for SPs.
    * Unified the tracking of all virtual interrupts:
        * Deprecated the `HF_INTERRUPT_DEACTIVATE` ABI for handling secure interrupts, as it wasn't
          needed for others.
        * Virtual interrupts returned in the order they were pended via `HF_INTERRUPT_GET`.
        * Cleared the state of virtual interrupts when returning `FFA_INTERRUPT` to an S-EL0
          partition.
    * Unconditionally cleared the ME interrupt when the SP enters the waiting state.
    * Multiple SPs can send an IPI targeting vCPUs pinned to the same physical core.
    * SPs can subscribe to CPU power off event and SPMC informs it through a FF-A direct request
      with a power management framework message.
    * Allowed memory regions defined in the SP manifest using `load-address-relative-offset` to
      overlap with the SP's address space — useful for setting permissions to specific regions.

* Bug fixes:
    * The `dlog` functions did not handle the `%*` format specifier. This is now supported.
    * Corrected the Schedule Receiver Interrupt priority to fit within the 'non-secure' interrupt
      priority range.
    * Fixed an issue where, with MTE enabled, the synchronous exception handler did not cover all
      exception codes.
    * The `FFA_PARTITION_INFO_GET` ABI now provides partition information with multiple UUIDs only
      to those using FF-A v1.2 or later.
    * Previously, virtual interrupts targeting a vCPU in a waiting state (and migrated to another
      physical CPU) were simply queued. Now, the vCPU is resumed on the target CPU and the interrupt
      is signaled for handling.
    * When the SPMC intercepts an `FFA_MSG_WAIT` or `FFA_MSG_SEND_DIRECT_RESP`/
      `FFA_MSG_SEND_DIRECT_RESP2` and returns with `FFA_INTERRUPT`, it sets the SP in SPMC scheduled
      mode and masks all other interrupts.
    * In `FFA_MEM_RETRIEVE_REQ` ABI handling, if the flag to bypass multiple borrower checks is set,
      then exactly one receiver is expected.
    * Fixed incorrect reporting of pending notifications in `FFA_NOTIFICATION_INFO_GET` when none
      remained.
    * Enabled G1S interrupts if they were not previously enabled by EL3.
    * Fixed a memory leak during FF-A memory share/lend/donate operations, where a page allocated
      for the memory region descriptor could leak if a copy operation failed.
    * Fixed misreporting in the `FFA_FEATURES` interface regarding support of certain ABIs based on
      FF-A version.
    * The SPMC now accepts either the 32-bit or 64-bit version of the `FFA_SUCCESS` ABI in response
      to `FFA_SECONDARY_EP_REGISTER` from the SPMD.
    * Added support for specifying `FFA_VERSION_COMPILED` in GN build system options.

* Tests, scripts, testing framework and build:
    * Increased test coverage for the IPI feature: non-primary CPUs, multiple IPIs pending on a CPU,
      one-to-many tests, unit tests.
    * Improved performance of static checks using `clang-tidy` and `checkpatch.pl`.
    * `hftest.py` can now process logs with invalid UTF-8 bytes.
    * `hftest.py` can use the `HAFNIUM_FVP` environment variable to locate the FVP binary for
      spawning tests.
    * Added a Hafnium Hypervisor target built with FF-A v1.1 for testing integration with EL3 SPMC.
    * Revived Docker image to enable building the project on macOS.
    * Modified `kokoro/test_spmc.sh` to optionally continue running all tests even if some fail.
    * Added dedicated `make` rules for the various test scripts under `kokoro/*`.

* Miscellaneous:
    * The `ffa` module, encapsulating behavior specific to the Hypervisor and SPMC, was moved to
      `src/ffa`. Files were split for a tidier and more modular implementation.

## v2.12
### Highlights

* FF-A v1.2 (continued adoption):
    * Restrict use of the `FFA_VERSION` ABI: FF-A endpoint version is locked from the first
      FF-A ABI call handled in the SPMC.
    * `FFA_MSG_WAIT` ABI update:
        * Transfer the ownership of RX buffer from consumer to producer.
        * Bypass the mentioned transfer of ownership via dedicated flag.
    * Support for VM availibility messages:
        * Subscription through the FF-A manifest.
        * Discovery through `FFA_PARTITION_INFO_GET` only at the NS FF-A instance.
        * Relay the framework message to the subscribed partition.

* Runtime support:
    * `FFA_CONSOLE_LOG` ABI:
       * SPMC adds the string `[<SP ID> <vCPU ID>]` to line logs from SPs.
       * Console log for each partition is tracked per vCPU, to avoid corrupting the buffer
         from concurrent logging from the same partition.
    * Exceptions related to synchronous tag faults in S-EL2 are now logged.
    * FF-A memory management:
        * Support of the SMC64 ABI version of all FF-A memory management interfaces.
        * Handle GPF exception caused by accessing non-secure RX/TX buffers in the handling
          of FF-A memory management ABIs.
        * Support for sharing and lending device memory.
    * Allocate the boot parameters for Hafnium's initialisation functions in the memory
      pool.
    * Paravirtualized interface for sending IPI (`HF_INTERRUPT_SEND_IPI`).
        * IPI injected straight away to target vCPUs in the running state.
        * Sending `SRI` interrupt to the NWd, when the target vCPU is in the waiting state.
        * Report the partitions and vCPUs which require CPU cycles to handle IPI through
          `FFA_NOTIFICATION_INFO_GET`.
        * If target vCPU is in blocked/preempted state, then pend/queue the virtual
          interrupt.
    * Secure Interrupt handling:
        * Support for queueing secure interrupts.
        * Support for S-EL1 UP SPs to handle interrupts.
        * Support interrupts sent during runtime model for intialisation (`RTM_INIT`).
    * Always eret `FFA_RUN` to the target SP, regardless of if it has pending messages,
      secure interrupts or notifications.

* Hardware architecture support:
    * Architectural physical timer emulation for SPs.
    * TC platform enabled branch protection feature.
    * Support for platforms with non-linear GIC redistributor frames.
    * Enabled S-EL0 partitions Pointer Authentication feature.

* Tests, scripts, testing framework and build:
    * Improved readability of the error messages for failed assertions.
    * Enabled the build flags '-Wextra' and '-Wsign-compare'.
    * Definition of assertion helpers to check content of strings.
    * Using enum types for the FF-A ABIs, FF-A errors, and test SP service commands.
    * Toolchain upgrade to clang-18.
    * Improved performance of `clang-tidy`.
    * Always expand the `assert` macro, to make sure arguments are type checked even
      when `ENABLE_ASSERTIONS` is not enabled.
    * Adopted `FFA_CONSOLE_LOG` ABI on `dlog` instances from SPs.
    * Restricted the functions defined with `SERVICE_SETUP` macros to run on the primary
      core.
    * Support for using the generic timer in the test partitions.
    * Support for using a watchdog timer from NWd test VMs.
    * Added new system setup, loading S-EL1 UP partitions on top of SPMC.

* Bug fixes:
    * Incorrect calculation of number of FF-A boot information descriptors.
    * FF-A memory management:
        * Drop unnecessary check to instruction permissions in the handling of
         `FFA_MEM_RELINQUISH`.
        * Sender with no Write access to a given memory region is prevented from using
          the clear/zero memory flags, in the descriptor to `FFA_MEM_LEND`, `FFA_MEM_SHARE`
          or `FFA_MEM_DONATE`.
        * Checks to the `impdef` field in the FF-A memory access descriptor done in accordance
          to FF-A version.
        * Consider the memory region descriptor format according to FF-A version, when
          processing an hypervisor retrieve request.
    * Platform build options:
        * Attest the option `enable_mte` can only have legal values 0 or 1, to enable
          and disable MTE feature use, respectively.
        * Attest the options `gic_version` and `gic_enable_espi` are configured with
          correct values, according to what is supported in Hafnium.
        * Attest the option `branch_protection` can only be configured with values
          `standard`, `pac-ret`, `pac-ret+leaf` and `bti`.
    * FF-A Notifications:
        * Set framework notifications only when recipient supports notifications.
        * Delay SRI flag can only be used on `FFA_NOTIFICATION_SET` from SPs. Return
          `FFA_ERROR(FFA_INVALID_PARAMETERS)` in invocations from the NWd that use it.
        * Allow for a caller to invoke`FFA_NOTIFICATION_GET` specifying a vCPU ID different
          than the calling vCPU.
    * `FFA_FEATURES` ABI:
        * Reports `FFA_YIELD` only to SPs.
        * Reports `ME` and `NPI` VI Id to S-EL1 partitions only.
        * Reports `FFA_SECONDARY_EP_REGISTER` to MP partitions only.
        * Reports `FFA_MEM_PERM_SET/GET` to S-EL0 partitions only.
    * The `FFA_PARTITION_INFO_GET(_REGS)` ABI reports the support of indirect message and direct
      message request/response 2, considering the version of the caller.
    * Prevent secure interrupt from preempting an SP in `SPMC` scheduled mode.
    * Ensure the FF-A error codes are be 32-bit unsigned values.
    * The error return for `FFA_FEATURES` ABI is restricted to `FFA_ERROR(FFA_NOT_SUPPORTED)`
      according to the FF-A v1.2 specification.
    * Ensure that accesses to `GICD_CTLR` register are complete by checking the state of
      the bit RWP.
    * Add check that manifest declared memory regions shouldn't overlap with SPMC address
      space.
    * First vCPU to boot ever from any SP was booting with the wrong vCPU state, fixed to
      `VCPU_STATE_RUNNING`.
    * Correctly define stack for the test SPs.
    * Report error when there are too many UUIDs defined in the partition's FF-A manifest.
    * Fix out of tree buid: use of `OUT` make argument such that the output directory can point
      to another location other than out/project/reference.
    * Memory regions specified with offset relative to partition's image position, rather than
      partition package load-address.
    * The SPMC enables a physical interrupt when the SP enables the respective virtual interrupt,
      instead of enabling by default during load of owner SP.

* Miscellaneous:
    * Improved `dlog` functions with compile time type checking to the arguments of
      logged strings.
    * Reduced complexity of utility functions defined in `std.h`.
    * The documentation of FF-A manifest bindings now refer to TF-A documentation as the common
      resource for all reference SPMC implementations.
    * Simplified the code for handling the preemption of `FFA_MSG_WAIT`/`FFA_MSG_SEND_DIRECT_RESP`
      due to a pending interrupt.
    * Dropped legacy code/tests:
        * Legacy hypervisor tests for timer support in NWd VMs.
        * Legacy hypervisor interface `HF_INTERRUPT_INJECT` and respective tests.
        * Legacy hypervisor waiting list concept.
        * The linux kernel tests in the Hafnium tests scripts. Hafnium driver code supports the
          hypervisor runtime model not the SPMC.
        * The linux kernel and hafnium driver submodules.
        * Legacy hypervisor `FFA_RUN` ABI tests.
    * Refactored the code enforcing the `boot-order` according to FF-A boot protocol to use
      `list.h` header.
    * Refactored the UUID packing/unpacking functions.
    * Dropped the SRI state tracking within the SPMC, to simplify notifications code.

## v2.11
### Highlights

* FF-A v1.2 (continued adoption):
    * Direct messaging:
        * New ABIs `FFA_MSG_SEND_DIRECT_REQ2` and `FFA_MSG_SEND_DIRECT_RESP2`.
        * Support extended register set and use of service UUID.
    * Memory management:
        * ABIs support the impdef field in memory access descriptor.
        * Lend device memory from an SP to another SP, and from a VM to an SP.
    * Setup and discovery:
        * Support multiple UUIDs per SP, both in manifest parsing and
          `FFA_PARTITION_INFO_GET`.
        * The `FFA_FEATURES` ABI reports RX/TX buffer max size.
    * Support extended set of registers with `FFA_CONSOLE_LOG` for v1.2 SPs.

* Runtime support:
    * Trap SP access to AMU counters.
    * SIMD context:
	* Refactored Advanced SIMD/SVE save and restore operations.
        * Introduce context save and restore of SME registers.
        * Leverage the SMCCC SVE hint bit mask.
        * Trap SP access to SVE/SME registers.
    * Realm Management Extension support:
        * On `FFA_MEM_DONATE` or `FFA_MEM_LEND` from VM/OS Kernel to SPs, change the physical
          address space of the memory regions from non-secure to secure.
        * On `FFA_MEM_RECLAIM`, if memory's address space was changed from non-secure to secure
          address space, revert physical address space change (from secure to non-secure).
        * The SPMC can handle a Granule Protection Fault: exception handler refactored
          to trap the new `memcpy_trapped` function, which returns error if copy failed due to GPF.
        * FFA_PARTITION_INFO_GET and FFA_MSG_SEND2 interfaces return FFA_ERROR(FFA_ABORTED) in case
          of hitting a Granule Protection Fault.
    * SMMUv3:
        * Support for static DMA isolation of upstream devices.
        * Access from DMA capable devices are only permitted to specific memory regions
          via dedicated DMA properties in the memory region node of an partition manifest.
    * SPMC saves and restores the NS-EL1 system registers context, to help reduce memory from
      EL3 monitor.
    * GICv3 driver to support two security states for interrupts.

* Hardware architecture support:
    * New platform build for RD fremont.
    * TC platform remapped the UART devices.

* Tests, scripts and testing framework:
    * TF-A prebuilt image used in Hafnium tests updated to support v1.2 interfaces.
    * S-EL0 partitions bumped to FF-A v1.2 version in general functionality tests.
    * The `SERVICE_SELECT_MP` macro was added to allow for tests to target a different vCPU
      than the primary vCPU.
    * Various new tests added to cover the newly added functionalities.

* Bug fixes:
    * FF-A memory management:
        * `FFA_MEM_RELINQUISH` returns `FFA_ERROR(FFA_DENIED)`, if clear memory flag is used
          when borrower's permission is RO.
        * `FFA_MEM_RETRIEVE_REQ` returns `FFA_ERROR(FFA_DENIED)` if sender ID is not correct in
          memory region descriptor.
        * Hypervisor retrieve request updated to support FF-A v1.2 descriptors and avoid
          conflicting checks with normal retrieve requests from FF-A endpoints.
        * `FFA_MEM_RETRIEVE_REQ` returns `FFA_ERROR(FFA_INVALID_PARAMETERS)` if receiver count
          is zero in memory region descriptor.
    * Interrupt handling:
        * Secure interrupt implicit completion flag reset in the runtime model for `FFA_RUN`.
        * Intercept `FFA_MSG_SEND_DIRECT_RESP/FFA_MSG_SEND_DIRECT_RESP2` and `FFA_MSG_WAIT` if SP
          relinquishes CPU cycles with pending secure interrupts.
        * Ignore spurious interrupt 1023 when SP is executing.
        * Unwind call chain when intercepting a direct response, to avoid SPs crashing.
    * Check that platform exists before building.
    * `FFA_FEATURES` interface:
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if func ID is `FFA_EL3_INTR_HANDLE`, and
          call is from hyperviosr/OS kernel.
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if feature ID is `SRI`, and call is from SP.
        * SPMC returns `FFA_ERROR(FFA_NOT_SUPPORTED)` if feature ID is `NPI` or `ME`, and call is
          from Hypervisor/OS Kernel.
    * FF-A notifications:
        * Return error code `FFA_INVALID_PARAMETERS` when provided invalid partition IDs
          in `FFA_NOTIFICATION_BITMAP_CREATE/DESTROY` and `FFA_NOTIFICATION_BIND/UNBIND`.
        * Return error `FFA_INVALID_PARAMETERS` to `FFA_NOTIFICATION_SET` if flags that
          Must Be Zero are not.
        * The vCPU argument must be zero in `FFA_NOTIFICATION_SET` for global notifications,
          else return error `FFA_INVALID_PARAMETERS`.
    * FF-A Indirect messaging:
        * Fix the checks to messages offset and total size.
        * Validate that SPMC has mapped the hypervisor/OS Kernel RX/TX buffers before
          accessing the buffers.
    * The handling of `FFA_MSG_WAIT` shall not change the SPMC's internal state of the
      RX buffer.
    * The interfaces `FFA_MEM_PERM_SET/GET` return error `FFA_DENIED` if used after
      SP's initializing.
    * The `kokoro/test_spmc.sh` terminates when hitting a failure for runs that are not
      collecting coverage data.
    * Device memory regions are mapped with attributes nGnRnE.

* Misc:
    * Building multiple targets with a single command with PLATFORM variable, providing
      multiple targets separated by ','.
    * Dropped the clang toolchain from the 'prebuilts' submodule to save repository space.
    * Dropped implementation of `HF_INTERRUPT_INJECT` out of SPMC implementation, as it was
      designed for Hypervisor and has no use in the SPMC.
    * Code static checks were separated into a dedicated script.
    * The interfaces `FFA_RXTX_MAP` and `FFA_RXTX_UNMAP` are restricted to NS memory provided
      in the SPMC manifest.
    * Improved handling of device region nodes in SP manifest:
        * The ranges specified were restricted to those specified in the designated nodes of
          the SPMC manifest.
        * Check overlaps with other memory regions in the system, such as partitions address
          space.
    * Avoid tracking the sender ID and descriptor size for memory management ABIs, in
      Hafnium's mailbox internal structures.
    * Helpers to log the names of FF-A ABIs and FF-A error codes.
    * Increase timeout for tests in `kokoro/test_spmc.sh` to cater for CI speed.
    * Use bitfield structures for permissions and attributes from the FF-A memory access
      descriptors.

## v2.10
### Highlights

* FF-A v1.2 (continued adoption):
    * `FFA_YIELD` interface:
        * Allow to be invoked while endpoint's partition runtime model is
          either direct message request or secure interrupt handling.
        * Allow an endpoint to specify an optional timeout such that it can be
          rescheduled after appropriate time to avoid busy wait.
    * Handle the `FFA_ERROR` interface at the SPs initialisation runtime model
      to put the SP in an aborted state.
    * Support for Logical Secure Partitions at EL3, managed by the SPMD:
        * Direct messaging request from LSPs to SPs at the virtual FF-A instance.
        * Discovery of LSPs via `FFA_PARTITION_INFO_GET(_REGS)` interfaces.
    * Support flag to bypass multiple borrower checks as part of `FFA_MEM_RETRIEVE_REQ`
      handling.
    * Memory region nodes support addresses relative to partition's load address.
* Hardware architecture support:
    * Fix to SMCCC use on Hafnium, to support use of extended register set as per
      SMCCCv1.2 for FF-A v1.2 and above.
    * GICv3: Enable platforms to leverage Shared Peripheral Interrupts extended ranges.
    * New paravirtualized interfaces to reconfigure a physical interrupt at runtime:
      target CPU, disabling/enabling the secure interrupt, and changing interrupt's
      security state.
    * Leverage support of secure and non-secure set of page tables for SMMUv3 streams.
    * Platform description of secure and non-secure memory is mandatory in the  SPMC
      manifest.
    * Use security state information in the S2 page tables to invalidate SP's TLB.
* Tests, scripts and testing framework:
    * Test framework improved to add tests into the SP's intialisation, via means of
      a helper macro.
    * Removed duplicated set of tests that were used to enable support of EL0
      partitions.
    * Hypervisor build refactored to track the state of memory sharing operations.
    * Few memory sharing related tests to run on EL3 SPMC, and serve as an indicator
      about feature parity.
    * Added ability to perform test coverage analysis, via Hafnium's testing scripts.
    * Increased test coverage of memory sharing functionality.
* Bug fixes:
    * Various fixes to memory sharing functionality:
        * Clear memory operations retrieve security state from S2 translation
          attributes.
        * Validation to page count field in the composite memory descriptor.
        * No overlapping of memory constituents.
        * Restrict SP from doing lend/share/donate targeting a normal world borrower.
        * Processing of instruction permissions specified in the lend/share/donate
          and by the borrower in the memory retrieve operation.
        * Use the NS bit in the `FFA_MEM_RETRIEVE_RESP` from SPMC to SP.
    * Force uniqueness of boot order field in the partition's manifest.
    * Added `FFA_RUN` interface restriction towards vCPU cores migration.
    * Refactor use of locked vCPU structures in few identified scenarios, that
      were prone to creating deadlocks.
    * Fixed the version compatibility rules in handling of the `FFA_VERSION`
      interface.
* Misc:
    * Migration of Hafnium documentation as the reference Secure Partition Manager
      into its own pages, leveraging the sphinx documentation framework.
    * Free resources allocated to SP if it gets to an aborted state, including
      disabling any physical interrupts that might trigger.
    * Deprecation of legacy hypervisor calls `HF_MAILBOX_*_GET`.
    * Simplified code path in the handling of secure interrupts.
    * Added build option to specify build target, which allows for faster builds,
      e.g. `make PLATFORM=secure_aem_v8a_fvp_vhe`.

## v2.9
### Highlights

* FF-A v1.2 (early adoption)
    * Implemented `FFA_PARTITION_INFO_GET_REGS` ABI permitting discovery of
      secure partitions by the use of general purpose registers instead of RX/TX
      buffers.
    * `FFA_CONSOLE_LOG` ABI support is improved from earlier release. It permits
      handling multiple characters passed through general purpose registers.
      The intent is to deprecate the legacy `HF_DEBUG_LOG` hypercall in a next
      release.
    * Introduced `FFA_EL3_INTR_HANDLE` ABI permitting the delegation of Group0
      physical secure interrupt handling to EL3. A G0 interrupt triggered while
      an SP is running traps to S-EL2 and is routed to the SPMD by the use of
      this ABI. Conversely, a G0 interrupt triggered while the normal world runs
      traps to EL3.
* FF-A v1.1 interrupt handling
    * Added support for secure interrupt signalling to S-EL0 partitions.
    * Increased the maximum number of virtual interrupts supported by an SP to a
      platform defined value (default 1024). This lifts a limitation in which
      SPs were allowed to declare only the first 64 physical interrupt IDs.
    * Added the impdef 'other-s-interrupts-action' field to SP manifests
      specifying the action to be taken (queued or signaled) in response to a
      secure interrupt targetted to an SP that is not the currently running SP.
    * For S-EL1 SP vCPUs, enable the notification pending and managed exit
      virtual interrupts if requested in the manifest.
      For S-EL0 SP vCPUs, enable virtual interrupts IDs matching the secure
      physical interrupt IDs declared in device regions.
    * Allow a physical interrupt declared in a SP manifest device region to be
      routed to any PE specified by its MPIDR. Introduce the 'interrupts-target'
      manifest field for this purpose.
* FF-A v1.1 memory sharing
    * Implemented changes to memory sharing structures to support FF-A backwards
      compatibility updates in the specification. The SPMC implementation caters
      for the case of existing FF-A v1.0 endpoints on top of the FF-A v1.1 SPMC.
      The latter performs the necessary conversions in the memory sharing
      structures.
    * Implemented capability to share/lend/donate memory to multiple borrowers
      including VMs or SPs.
    * Fragmented memory sharing is supported between normal world and secure
      world endpoints.
* FF-A v1.1 power management
    * Added the impdef 'power-management-messages' field to SP manifests
      specifying the type of power management events relayed to the SPMC.
    * Removed the limitation in which the first SP must be a MP SP.
      The configuration where all deployed SPs are S-EL0 SPs is now supported.
* FF-A v1.1 Indirect messaging
    * Updated mailbox internal state structures to align with RX/TX buffer
      synchronization rules (buffer state and ownership transfer).
* Misc and bug fixes
    * Introduced SPMC manifest memory region nodes specifying the system address
      ranges for secure and non-secure memory. This permits further hardening in
      which the SPMC needs to know the security state of a memory range. This
      helps boot time validation of SP manifests, and run-time checks in the
      memory sharing protocol.
    * SP manifest memory regions validation is hardened such that one SP cannot
      declare a memory region overlapping another SP's memory region.
    * Drop dynamic allocation of memory region base address. The option for
      declaring a memory region without its base address (and let the SPMC
      choose it) is removed.
    * Fixed handling of FEAT_LPA/FEAT_LPA2.
    * SMMUv3: fix SIDSIZE field usage.
    * GIC: fixed interrupt type configuration (edge/level).
* CI and test infrastructure
    * Migration to LLVM/clang 15.0.6
    * Removal of non-VHE configurations. Keep only configurations assuming
      Armv8.1 Virtualization Host Extensions is implemented. This implies
      HCR_EL2.E2H is always set. This change is transparent for the end user as
      configurations supported with VHE enabled are a superset of legacy non-VHE
      configurations.
    * EL3 SPMC: added test configurations to permit testing TF-A's EL3 SPMC
      by the use of Hafnium's CI test and infrastructure. The goal is to improve
      the test coverage for this alternative SPMC configuration and maintain a
      feature set parity with the S-EL2 SPMC.
    * Added debug capabilities to hftest script.

### Known limitations:
* Power management support limits to cpu on and cpu off events. Only S-EL1
  partitions can opt in for power management events. A power management
  event is forwarded from the SPMD to the SPMC and isn't forwarded to a SP.

## v2.8
### Highlights

* FF-A v1.1 partition runtime model and CPU cycle allocation modes
    * Implemented partition runtime models for secure partitions entered at
      initialization, processing a secure interrupt or as a result of allocation
      of CPU cycles by `FFA_RUN` and `FFA_MSG_SEND_DIRECT_REQ` ABIs invocations.
    * Added state machine checks related to above, in which a partition has a
      set of allowed transitions to enter and exit a partition runtime model.
    * Implemented CPU cycle allocation modes and winding/unwinding of call
      chains.
    * Refactored managed exit field in manifests to use one of the possible
      "Action for a non-secure interrupt" defined by the specification.
    * Added support for preferred managed exit signal (among vIRQ or vFIQ).
    * Support for precedence of the NS interrupt action in unwinding a normal
      world scheduled call chain.
* FF-A v1.1 memory sharing
    * Preparation changes for multiple borrowers and fragmented memory
      sharing support.
    * Fixed memory attributes checks as they are passed to memory sharing
      primitives (`FFA_MEM_SHARE/LEND/DONATE` and `FFA_MEM_RETRIEVE_REQ`).
    * Memory sharing support for S-EL0 partitions.
* FF-A v1.1 notifications
    * Added framework notifications support.
      The supported use case is for indirect messaging to notify a partition
      about a message pending in its RX buffer (or 'RX buffer full' framework
      notification).
    * Added support for notification pending interrupt injection on a RX buffer
      full event.
* FF-A v1.1 Indirect messaging
    * Added support for VM-VM, VM-SP, SP-SP indirect messaging scenarios.
    * Added partition message header structures.
    * Implemented `FFA_MSG_SEND2` and `FFA_RX_ACQUIRE` ABIs.
    * Refactored VM internal state tracking in the SPMC to support forwarding
      of RX/TX buffer mapping/unmapping, notifications creation/destruction,
      RX buffer acquire/release.
    * Refactored VM mailbox states to support the RX buffer full event.
* FF-A console log ABI
    * Added the `FFA_CONSOLE_LOG` ABI as a simple and standardized means to print
      characters without depending on an MMIO device mapped into the VM.
      This allows a VM to print debug or information strings through an
      hypervisor call service using general-purpose registers rather than a
      shared buffer. Multiple VMs can use the ABI concurrently as the SPMC
      buffers data per VM and serializes output to the physical serial device.
* FF-A v1.1 Setup & Discovery
    * Updated the `PARTITION_INFO_GET` ABI to return the partition UUID in the
      partition information descriptors. Additionaly the partition information
      descriptor size is returned as part of the response.
    * Added `FFA_MEM_FRAG_RX/TX` as supported interface in `FFA_FEATURE` response.
* Image footprint optimization
    * The following updates were made with the general idea of reducing the
      flash and RAM footprints. They are also means to adjust the memory
      utilization based on the target market segment.
        * Added platform defines to state the per-VM maximum number of memory and
          device regions, interrupts and SMMU streams per device.
        * Dynamically allocate per vCPU notifications.
        * Allocate vCPU structures from heap.
        * Manifest data allocation from page pool.
        * Fixed core stacks section with noload attribute.
* GIC
    * Added support for GICv3.1 extended SPI / PPI INTID ranges.
    * Add build options to extend the number of supported virtual interrupt IDs.
* SVE
    * Detect the platform supported SVE vector length or set the limit for the
      lower ELs.
    * Increased the SVE NS context to support the maximum vector length
      permitted by the architecture.
    * Above changes lift the limit about a fixed sized SVE vector length (of
      512 bits) used in earlier releases.
* Misc
    * Partition manifest parsing:
        * Added checks forbidding SPs to declare overlapping memory regions and
	  conflicting device interrupt ID resources.
        * Add ability to specify the security state of a memory region
	  for S-EL0 partitions.
    * Fixed system register trap exception injection.
    * Removed hypervisor tables defragmentation.
    * Add ability to define a log level per platform.
    * Disable alignment check for EL0 partitions (when VHE is enabled).

### Known limitations:
* S-EL0 partitions interrupt handling is work in progress.
* Normal world to secure world fragmented memory sharing and sharing to multiple
  borrowers is work in progress.

## v2.7
### Highlights

* Boot protocol (FF-A v1.1 EAC0)
    * The SPMC primarily supports passing the SP manifest address at boot time.
    * In a secure partition package, partition manifest and image offsets are
      configurable.
      * Allows for larger partition manifest sizes.
* Setup and discovery (FF-A v1.1 EAC0)
    * `FFA_VERSION` is forwarded from SPMD to SPMC. SPMC records the version of
      a normal world endpoint.
    * Added UUID to partition info descriptors.
    * Introduced count flag to `FFA_PARTITION_INFO_GET`.
* Interrupt handling (FF-A v1.1 Beta0)
    * Physical GIC registers trapped when accessed from secure partitions.
    * Priority mask register saved/restored on world switches.
    * Interrupts masked before resuming a pre-empted vCPU.
    * Implemented implicit secure interrupt completion signal.
    * Allow unused GICR frame for non-existent PEs.
* Notifications (FF-A v1.1 EAC0)
    * Implemented notification pending interrupt and additional test coverage.
* MTE stack tagging
    * Implemented `FEAT_MTE2` stack tagging support at S-EL2.
    * Core stacks marked as normal tagged memory. A synchronous abort triggers
      on a load/store tag check failure.
    * This permits detection of wrong operations affecting buffers allocated
      from the stack.
* FF-A v1.0 compliance
    * Check composite memory region offset is defined in FF-A memory sharing.
    * Check sender and receiver memory attributes in a FF-A memory sharing
      operation match the attributes expected in the Hafnium implementation.
    * Fix clear memory bit use in FF-A memory sharing from NWd to SWd.
    * Prevent FF-A memory sharing from a SP to a NS endpoint.
    * Reject a FF-A memory retrieve operation with the 'Address Range Alignment
      Hint' bit set (not supported by the implementation).
    * Refine usage of FF-A memory sharing 'clear memory flag'.
* Misc
    * Improved extended memory address ranges support:
        * 52 bits PA (`FEAT_LPA`/`FEAT_LPA2`) architecture extension detected
	  results in limiting the EL2 Stage-1 physical address range to 48 bits.
        * In the FF-A memory sharing operations, harden address width checks on
	  buffer mapping.
    * Improved MP SP and S-EL0 partitions support
      * The physical core index is passed to a SP vCPU0 on booting.
      * Added MP SP and S-EL0 partitions boot test coverage.
    * Emulate SMCCC VERSION to the primary VM.
    * Memory config registers (non-secure and secure virtualization control and
      translation table base) moved to the vCPU context.
    * EL2 stage 1 mapping extended to 1TB to support systems with physical
      address space larger than 512GB.
    * `FFA_RUN` ABI hardened to check the vCPU index matches the PE index onto
      which a vCPU is requested to run.
    * Fixed missing ISB after `CPTR_EL2` update upon PE initialization.
    * Fixed stage 2 default shareability to inner shareable (from non-shareable)
      to better support vCPU migration.
    * Fixed manifest structure allocation from BSS rather than stack
      at initialization.
    * Fixed an issue with FF-A memory reclaim executed after memory donate
      resulting in a returned error code.
* Build and test environment
    * Add the ability to use an out-of-tree toolchain.
      * Primary intent is to permit building Hafnium on Aarch64 hosts.
      * CI runs using the toolchain versioned in prebuilts submodule.
        A developer can still use this version as well.
    * Introduce an assert macro enabled by a build option on the command line.
      Assertions are checked by default. Production builds can optionally
      disable assertions.
    * Added manifest options to permit loading VMs using an FF-A manifest.
* CI
    * Added job running the Hypervisor + SPMC configuration on patch
      submissions.
    * FVP
      * Enable secure memory option.
      * Remove restriction on speculative execution options.
      * Updated to use model version 11.17 build 21.
    * Updated linux submodule to v5.10.
    * VHE EL0 partitions tests automated through jenkins.

### Known limitations:
* FF-A v1.1 EAC0 implementation is partial mainly on interrupt handling and
  memory sharing.
* Hafnium limits physical interrupt IDs to 64. The legacy virtual interrupt
  controller driver limits to 64. The recent addition of physical interrupt
  handling in the SPMC through the GIC assumes a 1:1 mapping of a physical
  interrupt ID to a virtual interrupt ID.
* Secure timer virtualization is not supported.
* The security state of memory or device region cannot be specified in a SP
  manifest.

## v2.6
### Highlights
* FF-A Setup and discovery
    * FF-A build time version updated to v1.1.
    * Managed exit and notifications feature support enabled in SP manifests.
    * Updated `FFA_FEATURES` to permit discovery of managed exit, schedule receiver,
      and notification pending interrupt IDs.
    * `FFA_PARTITION_INFO_GET` updated to permit managed exit and notification
      support discovery.
    * `FFA_SPM_ID_GET` added to permit discovering the SPMC endpoint ID (or the
      SPMD ID at the secure physical FF-A instance).
    * `FFA_RXTX_UNMAP` implementation added.
* FF-A v1.1 notifications
    * Added ABIs permitting VM (or OS kernel) to SP, and SP to SP asynchronous
      signaling.
    * Added generation of scheduler receiver (NS physical) and notification
      pending (secure virtual) interrupts.
    * The schedule receiver interrupt is donated from the secure world SGI
      interrupt ID range.
* FF-A v1.1 interrupt handling
    * Added a GIC driver at S-EL2 permitting to trap and handle non-secure and
      secure interrupts while the secure world runs.
    * Added forwarding and handling of a secure interrupt while the normal world
      runs.
    * Added secure interrupt forwarding to the secure partition that had the
      interrupt registered in its partition manifest.
    * The interrupt deactivation happens through the Hafnium para-virtualized
      interrupt controller interface.
    * vCPU states, run time models and SP scheduling model are revisited as per
      FF-A v1.1 Beta0 specification (see 'Known limitations' section below).
* S-EL0 partitions support
    * Added support for VHE architecture extension in the secure world (through
      a build option).
    * A partition bootstraps as an S-EL0 partition based on the exception-level
      field in the FF-A manifest.
    * It permits the implementation of applications on top of Hafnium without
      relying on an operating system at S-EL1.
    * It leverages the EL2&0 Stage-1 translation regime. Apps use FF-A
      ABIs through the SVC conduit.
    * Added FF-A v1.1 `FFA_MEM_PERM_GET/SET` ABIs permitting run-time update of
      memory region permissions.
    * It supersedes the existing S-EL1 shim architecture (without removing its
      support).
    * S-EL1 SP, S-EL0 SP or former S-EL0 SP+shim can all co-exist in the same
      system.
* SVE
    * Support for saving/restoring the SVE live state such that S-EL2/Hafnium
      preserves the normal world state on world switches.
    * Secure partitions are permitted to use FP/SIMD while normal world uses
      SVE/SIMD/FP on the same core.
    * The SVE NS live state comprises FPCR/FPSR/FFR/p[16]/Z[32] registers.
* LLVM/Clang 12
    * The toolchain stored in prebuilts submodule is updated to LLVM 12.0.5.
    * Build/static analyzer fixes done in the top and third party projects.
    * Linux sources (used by the test infrastructure) are updated to 5.4.148.
      The linux test kernel module build is updated to only depend on LLVM
      toolchain.
* Hafnium CI improvements
    * Added two configurations permitting Hafnium testing in the secure world.
    * First configuration launches both the Hypervisor in the normal world
      and the SPMC in the secure world. This permits thorough FF-A ABI testing
      among normal and secure world endpoints.
    * The second configuration launches the SPMC alone for component testing
      or SP to SP ABI testing.
    * Hafnium CI Qemu version updated to v6.0.0 (implements VHE and `FEAT_SEL2`
      extensions).
* FF-A compliance fixes
    * Added checks for valid memory permissions values in manifest memory and
      device regions declarations.
    * `FFA_FEATURES` fixed to state indirect messages are not supported by
      the SPMC.
    * Limit an SP to emit a direct request to another SP only.
    * Memory sharing: fixed input validation and return values.
    * `FFA_RXTX_MAP` fixed returned error codes.
    * `FFA_MSG_WAIT` input parameters check hardened.

### Known limitations:
* S-EL0 partitions/VHE: the feature is in an experimental stage and not all use
  cases have been implemented or tested. Normal world to SP and SP to SP memory
  sharing is not tested. Interrupt handling is not tested.
* The current implementation does not support handling a secure interrupt that
  is triggered while currently handling a secure interrupt. This restricts to
  scenarios described in Table 8.13 and Table 8.14 of the FF-A v1.1 Beta0
  specification. Priority Mask Register is not saved/restored during context
  switching while handling secure interrupt.
* Hafnium CI: scenarios involving the Hypervisor are left as test harness
  purposes only, not meant for production use cases.

## v2.5
### Highlights
* BTI/Pointer authentication support
    * Add branch protection build option for `FEAT_PAuth` and `FEAT_BTI` to the
      clang command line. This only affects the S-EL2 image.
    * Enable pointer authentication by supplying a platform defined pseudo
      random key.
    * Enable BTI by setting the guarded page bit in MMU descriptors for
      executable pages.
* SMMUv3.2 S-EL2 support
    * Add support for SMMUv3 driver to perform stage 2 translation, protection
      and isolation of upstream peripheral device's DMA transactions.
* FF-A v1.0 Non-secure interrupt handling
    * Trap physical interrupts to S-EL2 when running a SP.
    * Handle non secure interrupts that occur while an SP is executing,
      performing managed exit if supported.
    * Add basic support for the GICv3 interrupt controller for the AArch64
      platform.
* FF-A power management support at boot time
    * Provide platform-independent power management implementations for the
      Hypervisor and SPMC.
    * Implement the `FFA_SECONDARY_EP_REGISTER` interface for an MP SP or SPMC
      to register the secondary core cold boot entry point for each of their
      execution contexts.
    * Introduce a generic "SPMD handler" to process the power management events
      that may be conveyed from SPMD to SPMC, such as core off.
* FF-A Direct message interfaces
    * Introduce SP to SP direct messaging.
    * Fix bug in the MP SP to UP SP direct response handling.
* FF-A Memory sharing interfaces
    * Introduce SP to SP memory sharing.
    * When a sender of a memory management operation reclaims memory, set the
      memory regions permissions back to it's original configuration.
    * Require default permissions to be supplied to the function
      `ffa_memory_permissions_to_mode`, so in the case where no permissions are
      specified for a memory operation, the data and instruction permissions can
      be set to the default.
    * Encode Bit[63] of the memory region handle according to if the handle is
      allocated by the Hypervisor or SPMC.
* FF-A v1.0 spec compliance
    * Return `INVALID_PARAMETER` error code instead of `NOT_SUPPORTED` for direct
      messaging interfaces when an invalid sender or receiver id is given.
    * Check that reserved parameter registers are 0 when invoking direct
      messaging ABI interfaces.
    * For SMC32 compliant direct message interfaces, only copy 32-bits
      parameter values.
    * Change the FF-A error codes to 32-bit to match the FF-A specification.
    * Fix consistency with maintaining the calling convention bit of the
      func id between the `ffa_handler` and the `FFA_FEATURES` function.
* Remove primary VM dependencies in the SPMC
    * Treat normal world as primary VM when running in the secure world.
    * Create an SPMC boot flow.
* Hafnium CI
    * Enable Hafnium CI to include tests for Hafnium SPMC.
    * Add basic exception handler to service VM's.
* SIMD support
    * Add saving/restoring of other world FP/NEON/SIMD state when entering and
      exiting the SPMC.
* SPMC early boot cache fix
    * Import data cache clean and invalidation helpers from TF-A project and
      provide an arch module for cache operations.
    * Invalidate the SPMC image in the data cache at boot time to prevent
      potential access to stale cache entries left by earlier boots stages.
* Misc and bug fixes
    * Complete vCPU state save prior to normal world exit.
    * Update S-EL2 Stage-1 page table shareability from outer to inner.
    * Add PL011 UART initialization code to set the IDRD and FBRD registers
      according to the UART clock and baud rate specified at build time.
    * License script checker fixes.

### Known limitations:
* Secure interrupts not supported.
* FF-A indirect message interface not supported in the secure world.
* Only supporting models of MultiProcessor SP (vCPUs pinned to physical
  CPUs) or UniProcessor SP (single vCPU).
* The first secure partition booted must be a MP SP.
* `FFA_RXTX_UNMAP` not implemented.
* Use of an alternate caller provided buffer from RX/TX buffers for memory
  sharing operations is not implemented.
* A memory retrieve request to SPMC does not support the caller endpoint to
  provide the range of IPA addresses to map the region to.

## v2.4

This is the first drop to implement the TrustZone secure side S-EL2 firmware
(SPM Core component) complying with FF-A v1.0.
It is a companion to the broader TF-A v2.4 release.
The normal world Hypervisor is maintained functional along with the
Hafnium CI test suite.

### Highlights
* FF-A v1.0 Setup and discovery interface
    * Hypervisor implementation re-used and extended to the SPMC and SPs.
    * Added partition info get ABI and appropriate properties response depending
      on partition capabilities (PVM, Secondary VM or Secure Partitions).
    * FF-A device-tree manifest parsing.
    * FF-A partitions can declare memory/device regions, and RX/TX buffers that
      the SPMC sets up in the SP EL1&0 Stage-2 translation regime at boot time.
    * FF-A IDs normal and secure world split ranges.
    * The SPMC maps the Hypervisor (or OS kernel) RX/TX buffers as non-secure
      buffers in its EL2 Stage-1 translation regime on `FFA_RXTX_MAP` ABI
      invocation from the non-secure physical FF-A instance.
* FF-A v1.0 Direct message interface
    * Added implementation for the normal world Hypervisor and test cases.
    * Implementation extended to the SPMC and SPs.
    * Direct message requests emitted from the PVM to a Secondary VM or a
      Secure Partition (or OS Kernel to a Secure Partition). Direct message
      responses emitted from Secondary VMs and Secure Partitions to the PVM.
    * The secure world represents the "other world" (normal world Hypervisor
      or OS kernel) vCPUs in an abstract "Hypervisor VM".
* FF-A v1.0 memory sharing
    * Hypervisor implementation re-used and extended to the SPMC and SPs.
    * A NS buffer can be shared/lent/donated by a VM to a SP (or OS Kernel
      to a SP).
    * The secure world configures Stage-1 NS IPA output to access the NS PA
      space.
    * The secure world represents the "other world" (normal world Hypervisor
      or OS kernel) memory pages in an abstract "Hypervisor VM" and tracks
      memory sharing permissions from incoming normal world requests.
* Secure world enablement
    * Secure Partitions booted in sequence on their primary execution context,
      according to the boot order field in their partition manifest.
      This happens during the secure boot process before the normal world
      actually runs.
    * The SPMC implements the logic to receive FF-A messages through the EL3
      SPMD, process them, and either return to the SPMD (and normal world) or
      resume a Secure Partition.
    * Extract NS bit from `HPFAR_EL2` on Stage-2 page fault.
    * Prevent setup of LOR regions in SWd.
    * Avoid direct PSCI calls down to EL3.
* Platforms
    * Added Arm FVP secure Hafnium build support.
    * Added Arm TC0 "Total Compute" secure Hafnium build support.
* Other improvements
    * Re-hosting to trustedfirmware.org
    * `busy_secondary` timer increased to improve CI stability.
    * Removed legacy Hypervisor calls.
    * Fix `CPTR_EL2` TTA bit position.
    * Report `FAR_EL2` on injecting EL1 exception.
### Known limitations:
* Not all fields of the FF-A manifest are actually processed by the Hafnium
  device-tree parser.
* SP to SP communication not supported.
* SP to SP memory sharing not supported.
* S-EL1 and SIMD contexts shall be saved/restored by EL3.
* Multi-endpoint memory sharing not supported.
* Interrupt management limited to trapping physical interrupts to
  the first S-EL1 SP. Physical interrupt trapping at S-EL2 planned as
  next release improvement.
* Validation mostly performed using first SP Execution Context (vCPU0). More
  comprehensive multicore enablement planned as next release improvement.
