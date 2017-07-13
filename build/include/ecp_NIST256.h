#ifndef ECP_NIST256_H
#define ECP_NIST256_H

#include "fp_NIST256.h"
#include "config_curve_NIST256.h"

/* Curve Params - see rom_zzz.c */
extern const int CURVE_A_NIST256     /**< Elliptic curve A parameter */
extern const int CURVE_B_I_NIST256
extern const BIG_256_56 CURVE_B_NIST256     /**< Elliptic curve B parameter */
extern const BIG_256_56 CURVE_Order_NIST256 /**< Elliptic curve group order */
extern const BIG_256_56 CURVE_Cof_NIST256   /**< Elliptic curve cofactor */

/* Generator point on G1 */
extern const BIG_256_56 CURVE_Gx_NIST256 /**< x-coordinate of generator point in group G1  */
extern const BIG_256_56 CURVE_Gy_NIST256 /**< y-coordinate of generator point in group G1  */


/* For Pairings only */

/* Generator point on G2 */
extern const BIG_256_56 CURVE_Pxa_NIST256 /**< real part of x-coordinate of generator point in group G2 */
extern const BIG_256_56 CURVE_Pxb_NIST256 /**< imaginary part of x-coordinate of generator point in group G2 */
extern const BIG_256_56 CURVE_Pya_NIST256 /**< real part of y-coordinate of generator point in group G2 */
extern const BIG_256_56 CURVE_Pyb_NIST256 /**< imaginary part of y-coordinate of generator point in group G2 */

extern const BIG_256_56 CURVE_Bnx_NIST256 /**< BN curve x parameter */

extern const BIG_256_56 CURVE_Cru_NIST256 /**< BN curve Cube Root of Unity */

extern const BIG_256_56 CURVE_Fra_NIST256 /**< real part of BN curve Frobenius Constant */
extern const BIG_256_56 CURVE_Frb_NIST256 /**< imaginary part of BN curve Frobenius Constant */


extern const BIG_256_56 CURVE_W_NIST256[2]	 /**< BN curve constant for GLV decomposition */
extern const BIG_256_56 CURVE_SB_NIST256[2][2] /**< BN curve constant for GLV decomposition */
extern const BIG_256_56 CURVE_WB_NIST256[4]	 /**< BN curve constant for GS decomposition */
extern const BIG_256_56 CURVE_BB_NIST256[4][4] /**< BN curve constant for GS decomposition */


/**
	@brief ECP structure - Elliptic Curve Point over base field
*/

typedef struct
{
    int inf /**< Infinity Flag - not needed for Edwards representation */

    FP_NIST256 x /**< x-coordinate of point */
#if CURVETYPE_NIST256!=MONTGOMERY
    FP_NIST256 y /**< y-coordinate of point. Not needed for Montgomery representation */
#endif
    FP_NIST256 z/**< z-coordinate of point */
} ECP_NIST256


/* ECP E(Fp) prototypes */
/**	@brief Tests for ECP point equal to infinity
 *
	@param P ECP point to be tested
	@return 1 if infinity, else returns 0
 */
extern int ECP_NIST256_isinf(ECP_NIST256 *P)
/**	@brief Tests for equality of two ECPs
 *
	@param P ECP instance to be compared
	@param Q ECP instance to be compared
	@return 1 if P=Q, else returns 0
 */
extern int ECP_NIST256_equals(ECP_NIST256 *P,ECP_NIST256 *Q)
/**	@brief Copy ECP point to another ECP point
 *
	@param P ECP instance, on exit = Q
	@param Q ECP instance to be copied
 */
extern void ECP_NIST256_copy(ECP_NIST256 *P,ECP_NIST256 *Q)
/**	@brief Negation of an ECP point
 *
	@param P ECP instance, on exit = -P
 */
extern void ECP_NIST256_neg(ECP_NIST256 *P)
/**	@brief Set ECP to point-at-infinity
 *
	@param P ECP instance to be set to infinity
 */
extern void ECP_NIST256_inf(ECP_NIST256 *P)
/**	@brief Calculate Right Hand Side of curve equation y^2=f(x)
 *
	Function f(x) depends on form of elliptic curve, Weierstrass, Edwards or Montgomery.
	Used internally.
	@param r BIG n-residue value of f(x)
	@param x BIG n-residue x
 */
extern void ECP_NIST256_rhs(FP_NIST256 *r,FP_NIST256 *x)
/**	@brief Set ECP to point(x,y) given just x and sign of y
 *
	Point P set to infinity if no such point on the curve. If x is on the curve then y is calculated from the curve equation.
	The correct y value (plus or minus) is selected given its sign s.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@param s an integer representing the "sign" of y, in fact its least significant bit.
 */
extern int ECP_NIST256_setx(ECP_NIST256 *P,BIG_256_56 x,int s)

#if CURVETYPE_NIST256==MONTGOMERY
/**	@brief Set ECP to point(x,[y]) given x
 *
	Point P set to infinity if no such point on the curve. Note that y coordinate is not needed.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_NIST256_set(ECP_NIST256 *P,BIG_256_56 x)
/**	@brief Extract x coordinate of an ECP point P
 *
	@param x BIG on exit = x coordinate of point
	@param P ECP instance (x,[y])
	@return -1 if P is point-at-infinity, else 0
 */
extern int ECP_NIST256_get(BIG_256_56 x,ECP_NIST256 *P)
/**	@brief Adds ECP instance Q to ECP instance P, given difference D=P-Q
 *
	Differential addition of points on a Montgomery curve
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
	@param D Difference between P and Q
 */
extern void ECP_NIST256_add(ECP_NIST256 *P,ECP_NIST256 *Q,ECP_NIST256 *D)
#else
/**	@brief Set ECP to point(x,y) given x and y
 *
	Point P set to infinity if no such point on the curve.
	@param P ECP instance to be set (x,y)
	@param x BIG x coordinate of point
	@param y BIG y coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_NIST256_set(ECP_NIST256 *P,BIG_256_56 x,BIG_256_56 y)
/**	@brief Extract x and y coordinates of an ECP point P
 *
	If x=y, returns only x
	@param x BIG on exit = x coordinate of point
	@param y BIG on exit = y coordinate of point (unless x=y)
	@param P ECP instance (x,y)
	@return sign of y, or -1 if P is point-at-infinity
 */
extern int ECP_NIST256_get(BIG_256_56 x,BIG_256_56 y,ECP_NIST256 *P)
/**	@brief Adds ECP instance Q to ECP instance P
 *
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
 */
extern void ECP_NIST256_add(ECP_NIST256 *P,ECP_NIST256 *Q)
/**	@brief Subtracts ECP instance Q from ECP instance P
 *
	@param P ECP instance, on exit =P-Q
	@param Q ECP instance to be subtracted from P
 */
extern void ECP_NIST256_sub(ECP_NIST256 *P,ECP_NIST256 *Q)
#endif
/**	@brief Converts an ECP point from Projective (x,y,z) coordinates to affine (x,y) coordinates
 *
	@param P ECP instance to be converted to affine form
 */
extern void ECP_NIST256_affine(ECP_NIST256 *P)
/**	@brief Formats and outputs an ECP point to the console, in projective coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_NIST256_outputxyz(ECP_NIST256 *P)
/**	@brief Formats and outputs an ECP point to the console, converted to affine coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_NIST256_output(ECP_NIST256 * P)

/**	@brief Formats and outputs an ECP point to the console
 *
	@param P ECP instance to be printed
 */
extern void ECP_NIST256_rawoutput(ECP_NIST256 * P)

/**	@brief Formats and outputs an ECP point to an octet string
 *
	The octet string is created in the standard form 04|x|y, except for Montgomery curve in which case it is 06|x
	Here x (and y) are the x and y coordinates in big-endian base 256 form.
	@param S output octet string
	@param P ECP instance to be converted to an octet string
 */
extern void ECP_NIST256_toOctet(octet *S,ECP_NIST256 *P)
/**	@brief Creates an ECP point from an octet string
 *
	The octet string is in the standard form 0x04|x|y, except for Montgomery curve in which case it is 0x06|x
	Here x (and y) are the x and y coordinates in left justified big-endian base 256 form.
	@param P ECP instance to be created from the octet string
	@param S input octet string
	return 1 if octet string corresponds to a point on the curve, else 0
 */
extern int ECP_NIST256_fromOctet(ECP_NIST256 *P,octet *S)
/**	@brief Doubles an ECP instance P
 *
	@param P ECP instance, on exit =2*P
 */
extern void ECP_NIST256_dbl(ECP_NIST256 *P)
/**	@brief Multiplies an ECP instance P by a small integer, side-channel resistant
 *
	@param P ECP instance, on exit =i*P
	@param i small integer multiplier
	@param b maximum number of bits in multiplier
 */
extern void ECP_NIST256_pinmul(ECP_NIST256 *P,int i,int b)
/**	@brief Multiplies an ECP instance P by a BIG, side-channel resistant
 *
	Uses Montgomery ladder for Montgomery curves, otherwise fixed sized windows.
	@param P ECP instance, on exit =b*P
	@param b BIG number multiplier

 */
extern void ECP_NIST256_mul(ECP_NIST256 *P,BIG_256_56 b)
/**	@brief Calculates double multiplication P=e*P+f*Q, side-channel resistant
 *
	@param P ECP instance, on exit =e*P+f*Q
	@param Q ECP instance
	@param e BIG number multiplier
	@param f BIG number multiplier
 */
extern void ECP_NIST256_mul2(ECP_NIST256 *P,ECP_NIST256 *Q,BIG_256_56 e,BIG_256_56 f)

#endif
