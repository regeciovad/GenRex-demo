# GenRex-demo
A set of Yara rules for demonstration of the GenRex tool. The tool itself will be published soon. 

The directory `rules` contains 10 Yara rules. The directory `stats` includes results from the evaluation.

Additionally, the `yara` folder contains an extension to the code for matching api_calls, atoms, resolved_apis, and semaphores.

The update also allows comparing a number of matched strings as in `cuckoo.genrex.semaphore(/LJpExtC8rffiNYPa94/) >=  2`.

The dataset of CAPE reports is available here: https://github.com/regeciovad/avast-ctu-cape-dataset/tree/reports_min.
