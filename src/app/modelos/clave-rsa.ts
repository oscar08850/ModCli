import * as bcu from 'bigint-crypto-utils';

export class RsaPrivateKey {
    d: bigint
    n: bigint

    constructor (d: bigint, n: bigint) {
        this.d = d
        this.n = n
    }

    decrypt (c: bigint): bigint {
        return bcu.modPow(c, this.d, this.n)
    }

    sign (m: bigint): bigint {
        return bcu.modPow(m, this.d, this.n)
    }
}
  
export class RsaPublicKey {
    e: bigint
    n: bigint

    constructor (e: bigint, n: bigint) {
        this.e = e
        this.n = n
    }

    encrypt (m: bigint): bigint {
        return bcu.modPow(m, this.e, this.n)
    }

    verify (s: bigint): bigint {
        return bcu.modPow(s, this.e, this.n)
    }
}

export class RsaPublicKeyPaillier {
  readonly n: bigint
  readonly g: bigint
  readonly _n2: bigint

  constructor (n: bigint, g: bigint) {
    this.n = n
    this._n2 = this.n ** 2n // cache n^2
    this.g = g
  }

  get bitLength (): number {
    return bcu.bitLength(this.n)
  }
  
  encrypt (m: bigint, r?: bigint): bigint {
    if (r === undefined) {
      do {
        r = bcu.randBetween(this.n)
      } while (bcu.gcd(r, this.n) !== 1n)
    }
    return (bcu.modPow(this.g, m, this._n2) * bcu.modPow(r, this.n, this._n2)) % this._n2
  }

  addition (...ciphertexts: Array<bigint>): bigint {
    return ciphertexts.reduce((sum, next) => sum * next % (this._n2), 1n)
  }

  /**
     * Pseudo-homomorphic Paillier multiplication
     *
     * @param {bigint} c - a number m encrypted with this public key
     * @param {bigint | number} k - either a bigint or a number
     *
     * @returns {bigint} - the encryption of k·m with this public key
     */
  multiply (c: bigint, k: bigint|number): bigint {
    return bcu.modPow(c, k, this._n2)
  }
}
  
export interface rsaKeyPair {
    publicKey: RsaPublicKey
    privateKey: RsaPrivateKey
}
  
export const generateKeys = async function (bitLength: number): Promise<rsaKeyPair> {
    const e = 65537n
    let p: bigint, q: bigint, n: bigint, phi: bigint
    do {
        p = await bcu.prime(bitLength / 2 + 1)
        q = await bcu.prime(bitLength / 2)
        n = p * q
        phi = (p - 1n) * (q - 1n)
    } while (bcu.bitLength(n) !== bitLength || (phi % e === 0n))

    const publicKey = new RsaPublicKey(e, n)

    const d = bcu.modInv(e, phi)

    const privKey = new RsaPrivateKey(d, n)

    return {
        publicKey,
        privateKey: privKey
    }
}
