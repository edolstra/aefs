incls = "-I{./} -I{./system} -I{./system/posix} -I{./ciphers} -I{./corefs}";
defs = "-DSYSTEM_posix -DAEFS_VERSION=\"AEFS0.2.1\"";
cflags = [incls defs];
