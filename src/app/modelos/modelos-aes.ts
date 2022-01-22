import { CifradoAES } from "./modelos";

export class keyAES {
    clave: CryptoKey

    constructor(){
    }

    async setup(claveHex?: Uint8Array){
        if (claveHex !== undefined){
            this.clave = await crypto.subtle.importKey(
                "raw",
                claveHex,
                "AES-GCM",
                true,
                ["encrypt", "decrypt"]
              )
        }

        else{
            this.clave = await crypto.subtle.generateKey(
                {
                  name: "AES-GCM",
                  length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );
        }
    }

    async cifrar(mensaje: Uint8Array): Promise<CifradoAES>{
        const iv: Uint8Array = window.crypto.getRandomValues(new Uint8Array(12));
        const cifrado: ArrayBuffer = await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: iv
            }, 
            this.clave, 
            mensaje
        )

        const datos: CifradoAES = {
            mensaje: new Uint8Array (cifrado),
            iv: iv
        }

        return datos;
    }

    async descifrar(mensaje: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        const descifrado: ArrayBuffer = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: iv
            },
            this.clave,
            mensaje
        )

        return new Uint8Array(descifrado)
    }

    async exportarClave(): Promise<Uint8Array> {
        const claveArray: ArrayBuffer = await window.crypto.subtle.exportKey("raw", this.clave);
        return new Uint8Array(claveArray)
    }
}
