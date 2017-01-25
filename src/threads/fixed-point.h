#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define F (1<<14)

#define convert_to_fixed(n) (n * F)
#define convert_to_int_z(x) (x / F)
#define convert_to_int_n(x) (x >= 0 ? ((x + F / 2) / F) : ((x - F / 2) / F) )
#define add_fixed_fixed(x,y) (x + y)
#define add_fixed_int(x,n) (x + n * F)
#define sub_fixed_fixed(x,y) (x - y)
#define sub_fixed_int(x,n) (x - n * F)
#define multiply_fixed_fixed(x,y) (( (int64_t)x ) * y / F)
#define multiply_fixed_int(x,n) (x * n)
#define divide_fixed_fixed(x,y) (( (int64_t)x ) * F / y)
#define divide_fixed_int(x,n) (x / n)

#endif // FIXED_POINT_H
