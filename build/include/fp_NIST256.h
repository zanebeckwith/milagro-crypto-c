#ifndef FP_NIST256_H
#define FP_NIST256_H

#include "big_256_56.h"
#include "config_field_NIST256.h"


/**
	@brief FP Structure - quadratic extension field
*/

typedef struct
{
    BIG_256_56 g	/**< Big representation of field element */
    sign32 XES	/**< Excess */
} FP_NIST256


/* Field Params - see rom.c */
extern const BIG_256_56 Modulus_NIST256	/**< Actual Modulus set in romf_yyy.c */
extern const BIG_256_56 R2modp_NIST256	/**< Montgomery constant */
extern const chunk MConst_NIST256		/**< Constant associated with Modulus - for Montgomery = 1/p mod 2^BASEBITS */


#define MODBITS_NIST256 MBITS_NIST256
#define TBITS_NIST256 (MBITS_NIST256%BASEBITS_256_56)                    /**< Number of active bits in top word */
#define TMASK_NIST256 (((chunk)1<<TBITS_NIST256)-1)               /**< Mask for active bits in top word */
#define FEXCESS_NIST256 ((sign32)1<<MAXXES_NIST256)				/**< 2^(BASEBITS*NLEN-MODBITS) - normalised BIG can be multiplied by more than this before reduction */
#define OMASK_NIST256 (-((chunk)(1)<<TBITS_NIST256))              /**<  for masking out overflow bits */

//#define FUSED_MODMUL
//#define DEBUG_REDUCE

/* FP prototypes */

/**	@brief Tests for FP equal to zero mod Modulus
 *
	@param x BIG number to be tested
	@return 1 if zero, else returns 0
 */
extern int FP_NIST256_iszilch(FP_NIST256 *x)


/**	@brief Set FP to zero
 *
	@param x FP number to be set to 0
 */
extern void FP_NIST256_zero(FP_NIST256 *x)

/**	@brief Copy an FP
 *
	@param y FP number to be copied to
	@param x FP to be copied from
 */
extern void FP_NIST256_copy(FP_NIST256 *y,FP_NIST256 *x)

/**	@brief Copy from ROM to an FP
 *
	@param y FP number to be copied to
	@param x BIG to be copied from ROM
 */
extern void FP_NIST256_rcopy(FP_NIST256 *y,const BIG_256_56 x)


/**	@brief Compares two FPs
 *
	@param x FP number
	@param y FP number
	@return 1 if equal, else returns 0
 */
extern int FP_NIST256_equals(FP_NIST256 *x,FP_NIST256 *y)


/**	@brief Conditional constant time swap of two FP numbers
 *
	Conditionally swaps parameters in constant time (without branching)
	@param x an FP number
	@param y another FP number
	@param s swap takes place if not equal to 0
 */
extern void FP_NIST256_cswap(FP_NIST256 *x,FP_NIST256 *y,int s)
/**	@brief Conditional copy of FP number
 *
	Conditionally copies second parameter to the first (without branching)
	@param x an FP number
	@param y another FP number
	@param s copy takes place if not equal to 0
 */
extern void FP_NIST256_cmove(FP_NIST256 *x,FP_NIST256 *y,int s)
/**	@brief Converts from BIG integer to residue form mod Modulus
 *
	@param x BIG number to be converted
	@param y FP result
 */
extern void FP_NIST256_nres(FP_NIST256 *y,BIG_256_56 x)
/**	@brief Converts from residue form back to BIG integer form
 *
	@param y FP number to be converted to BIG
	@param x BIG result
 */
extern void FP_NIST256_redc(BIG_256_56 x,FP_NIST256 *y)
/**	@brief Sets FP to representation of unity in residue form
 *
	@param x FP number to be set equal to unity.
 */
extern void FP_NIST256_one(FP_NIST256 *x)
/**	@brief Reduces DBIG to BIG exploiting special form of the modulus
 *
	This function comes in different flavours depending on the form of Modulus that is currently in use.
	@param r BIG number, on exit = d mod Modulus
	@param d DBIG number to be reduced
 */
extern void FP_NIST256_mod(BIG_256_56 r,DBIG_256_56 d)

#ifdef FUSED_MODMUL
extern void FP_NIST256_modmul(BIG_256_56,BIG_256_56,BIG_256_56)
#endif

/**	@brief Fast Modular multiplication of two FPs, mod Modulus
 *
	Uses appropriate fast modular reduction method
	@param x FP number, on exit the modular product = y*z mod Modulus
	@param y FP number, the multiplicand
	@param z FP number, the multiplier
 */
extern void FP_NIST256_mul(FP_NIST256 *x,FP_NIST256 *y,FP_NIST256 *z)
/**	@brief Fast Modular multiplication of an FP, by a small integer, mod Modulus
 *
	@param x FP number, on exit the modular product = y*i mod Modulus
	@param y FP number, the multiplicand
	@param i a small number, the multiplier
 */
extern void FP_NIST256_imul(FP_NIST256 *x,FP_NIST256 *y,int i)
/**	@brief Fast Modular squaring of an FP, mod Modulus
 *
	Uses appropriate fast modular reduction method
	@param x FP number, on exit the modular product = y^2 mod Modulus
	@param y FP number, the number to be squared

 */
extern void FP_NIST256_sqr(FP_NIST256 *x,FP_NIST256 *y)
/**	@brief Modular addition of two FPs, mod Modulus
 *
	@param x FP number, on exit the modular sum = y+z mod Modulus
	@param y FP number
	@param z FP number
 */
extern void FP_NIST256_add(FP_NIST256 *x,FP_NIST256 *y,FP_NIST256 *z)
/**	@brief Modular subtraction of two FPs, mod Modulus
 *
	@param x FP number, on exit the modular difference = y-z mod Modulus
	@param y FP number
	@param z FP number
 */
extern void FP_NIST256_sub(FP_NIST256 *x,FP_NIST256 *y,FP_NIST256 *z)
/**	@brief Modular division by 2 of an FP, mod Modulus
 *
	@param x FP number, on exit =y/2 mod Modulus
	@param y FP number
 */
extern void FP_NIST256_div2(FP_NIST256 *x,FP_NIST256 *y)
/**	@brief Fast Modular exponentiation of an FP, to the power of a BIG, mod Modulus
 *
	@param x FP number, on exit  = y^z mod Modulus
	@param y FP number
	@param z BIG number exponent
 */
extern void FP_NIST256_pow(FP_NIST256 *x,FP_NIST256 *y,BIG_256_56 z)
/**	@brief Fast Modular square root of a an FP, mod Modulus
 *
	@param x FP number, on exit  = sqrt(y) mod Modulus
	@param y FP number, the number whose square root is calculated

 */
extern void FP_NIST256_sqrt(FP_NIST256 *x,FP_NIST256 *y)
/**	@brief Modular negation of a an FP, mod Modulus
 *
	@param x FP number, on exit = -y mod Modulus
	@param y FP number
 */
extern void FP_NIST256_neg(FP_NIST256 *x,FP_NIST256 *y)
/**	@brief Outputs an FP number to the console
 *
	Converts from residue form before output
	@param x an FP number
 */
extern void FP_NIST256_output(FP_NIST256 *x)
/**	@brief Outputs an FP number to the console, in raw form
 *
	@param x a BIG number
 */
extern void FP_NIST256_rawoutput(FP_NIST256 *x)
/**	@brief Reduces possibly unreduced FP mod Modulus
 *
	@param x FP number, on exit reduced mod Modulus
 */
extern void FP_NIST256_reduce(FP_NIST256 *x)
/**	@brief normalizes FP
 *
	@param x FP number, on exit normalized
 */
extern void FP_NIST256_norm(FP_NIST256 *x)
/**	@brief Tests for FP a quadratic residue mod Modulus
 *
	@param x FP number to be tested
	@return 1 if quadratic residue, else returns 0 if quadratic non-residue
 */
extern int FP_NIST256_qr(FP_NIST256 *x)
/**	@brief Modular inverse of a an FP, mod Modulus
 *
	@param x FP number, on exit = 1/y mod Modulus
	@param y FP number
 */
extern void FP_NIST256_inv(FP_NIST256 *x,FP_NIST256 *y)




#endif
