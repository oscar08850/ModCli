import { RsaPublicKey } from './clave-rsa'

export interface Mensaje {
    usuario: string
    mensaje: string
}

export interface Usuario {
    nombre: string
    publicKey: RsaPublicKey
}

export interface UsuarioServidor {
    nombre: string
    eHex: string
    nHex: string
    nPaillierHex?: string
    gPaillierHex?: string
}

export interface MensajeServidor {
    usuario: string
    tipo: string
    cifrado: string
    iv: string
    clave?: string
}

export interface NoRepudio {
    usuarioOrigen: string
    usuarioDestino: string
    cifrado: string
    TimeStamp: string
    firma?: string
}

export interface CifradoRSA {
    cifrado: CifradoAES
    clave: string
}

export interface CifradoAES {
    mensaje: Uint8Array
    iv: Uint8Array
}

export interface Recuento {
    mensaje?: string
    recuento: string
}

export interface secretoCompartido {
    secreto: string
    shared: number
    threshold: number
}