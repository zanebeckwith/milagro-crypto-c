#ifndef CONFIG_CURVE_NIST256_H
#define CONFIG_CURVE_NIST256_H

#include"amcl.h"
#include"config_field_NIST256.h"

// ECP stuff

#define CURVETYPE_NIST256 WEIERSTRASS  
#define PAIRING_FRIENDLY_NIST256 NOT

/*
#define CURVETYPE_NIST256 EDWARDS 
#define PAIRING_FRIENDLY_NIST256 NOT
*/

#if PAIRING_FRIENDLY_NIST256 != NOT
#define USE_GLV_NIST256	  /**< Note this method is patented (GLV), so maybe you want to comment this out */
#define USE_GS_G2_NIST256 /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_NIST256 /**< Not patented, so probably safe to always use this */
#endif

#endif