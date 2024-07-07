## Zero-config (ZC) switchless
- This is a research project aimed to remove the need for configuring Intel SGX switchless calls at build time.
- Doing this obviates the performance degradation due to bad configurations.
- This repo follows our publication at the IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), 2023
```
@INPROCEEDINGS{10202647,
  author={Yuhala, Peterson and Paper, Michael and Zerbib, Timothée and Felber, Pascal and Schiavoni, Valerio and Tchana, Alain},
  booktitle={2023 53rd Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)}, 
  title={SGX Switchless Calls Made Configless}, 
  year={2023},
  volume={},
  number={},
  pages={229-238},
  keywords={Degradation;Context;Runtime;Codes;Instruction sets;Switches;Software;Intel SGX;trusted execution environments;SGX switchless calls;multithreading},
  doi={10.1109/DSN58367.2023.00032}}
```

## System architecture
![ZC switchless architecture](./imgs/architecture.pdf)
- The [in-application scheduler](./sgx/App/zcUntrusted/scheduler.cpp) periodically obtains application metrics such as number of fallback calls to determine the most appropriate number of worker threads to use for switchless calls.
- The number of worker threads is chosen in such a way as to minimize waste of CPU resources while providing good performance relative to a non-switchless system.
