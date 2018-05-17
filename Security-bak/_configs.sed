s/^#undef  *\([ABCDEFGHIJKLMNOPQRSTUVWXYZ_]\)/#undef NDN_CPP_\1/
s/^#undef  *\([abcdefghijklmnopqrstuvwxyz]\)/#undef _ndn_cpp_\1/
s/^#define  *\([ABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*\)\(.*\)/#ifndef NDN_CPP_\1\
#define NDN_CPP_\1\2\
#endif/
s/^#define  *\([abcdefghijklmnopqrstuvwxyz][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*\)\(.*\)/#ifndef _ndn_cpp_\1\
#define _ndn_cpp_\1\2\
#endif/
