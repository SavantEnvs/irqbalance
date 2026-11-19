// Disable LeakSanitizer for every fuzz and -standalone binary (leaks are not the bug class
// this fleet fuzzes for); ASan and UBSan stay fully active. Compiled as C by build.sh.
#ifdef __cplusplus
extern "C"
#endif
int __lsan_is_turned_off(void) { return 1; }
