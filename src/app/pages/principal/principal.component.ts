import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { Socket } from 'ngx-socket-io';
import { CifradoRSA, UsuarioServidor, Mensaje, MensajeServidor, CifradoAES, NoRepudio, secretoCompartido } from '../../modelos/modelos';
import { Usuario } from '../../modelos/modelos';
import * as bigintConversion from 'bigint-conversion';
import * as cryptojs from 'crypto-js';
import { RsaPublicKey } from '../../modelos/clave-rsa';
import { ServidorService } from 'src/app/services/servidor.service';

@Component({
  selector: 'app-principal',
  templateUrl: './principal.component.html',
  styleUrls: ['./principal.component.css']
})
export class PrincipalComponent implements OnInit {

  constructor(private servidorService: ServidorService, private changeDetectorRef: ChangeDetectorRef, private socket: Socket) { }

  mensaje: string;
  mensajeAlgoritmo: string;
  usuarioTextBox: string;
  usuario: string;
  usuarioNoRepudio: string;
  ivNoRepudio: Uint8Array;
  usuarios: Usuario[] = [];
  cifrado: string;
  errorCifrado: Boolean = false;
  errorMensaje: Boolean = false;
  errorMensajeAlgoritmo: Boolean = false;
  errorNombre: Boolean = false;
  errorElegido: Boolean = false;
  errorUsuario: Boolean = false;
  enviado: Boolean = false;
  recibido: Boolean = false;
  contestado: Boolean = false;
  noContestado: Boolean = false;
  disabled: Boolean = false;
  mensajeRecibido: Mensaje;
  mensajes: Mensaje[] = [];
  mensajesNoRepudio: Mensaje[] = [];
  mensajeNoRepudio: NoRepudio;
  candidato: string;
  errorVoto: Boolean = false;
  votado: Boolean = false;
  erroMax: Boolean = false;
  votosMarianoRajoy: string = "0";
  votosDonaldTrump: string = "0";
  votosJuanelas: string = "0";
  errorSecreto: Boolean = false;
  secreto: string;
  shared: number;
  threshold: number;
  clavesCompartidas: string[] = [];
  numClaves: number = 0;
  claves: string[] = [];
  errorClaves: Boolean = false;
  secretoRecuperado: string;
  errorRecuperado: Boolean = false;

  async ngOnInit(): Promise<void> {
    await this.servidorService.getClaves();
  }

  sockets(): void {
    this.socket.on('nuevoConectado', (usuarioSocket: UsuarioServidor) => {
      if (usuarioSocket.nombre !== this.usuario){
        const nuevoUsuario: Usuario = {
          nombre: usuarioSocket.nombre,
          publicKey: new RsaPublicKey(bigintConversion.hexToBigint(usuarioSocket.eHex), bigintConversion.hexToBigint(usuarioSocket.nHex))
        }
        this.usuarios.push(nuevoUsuario)
      }
    })

    this.socket.on('cambiarNombre', (usuariosSocket: string[]) => {
      if (this.usuario !== usuariosSocket[1]){
        this.usuarios.forEach((usuarioLista: Usuario) => {
          if (usuarioLista.nombre === usuariosSocket[0]){
            this.usuarios[this.usuarios.indexOf(usuarioLista)].nombre = usuariosSocket[1];
          }
        })
      }
    })

    this.socket.on('desconectado', (usuarioSocket: string) => {
      this.usuarios.forEach((usuarioLista: Usuario) => {
        if (usuarioLista.nombre === usuarioSocket)
          this.usuarios.splice(this.usuarios.indexOf(usuarioLista), 1)
      })
    })

    this.socket.on('nuevoMensaje', (mensajeSocket: Mensaje) => {
      if (mensajeSocket.usuario !== this.usuario){
        this.mensajes.push(mensajeSocket)
      }
    })

    this.socket.on('mensajeCifrado', (recibidoSocket: NoRepudio) => {
      if (this.mensajeNoRepudio === undefined){
        this.usuarios.forEach((usuarioLista: Usuario) => {
          if (usuarioLista.nombre === recibidoSocket.usuarioOrigen){
            const respuesta: NoRepudio = {
              usuarioOrigen: recibidoSocket.usuarioOrigen,
              usuarioDestino: recibidoSocket.usuarioDestino,
              cifrado: recibidoSocket.cifrado,
              TimeStamp: recibidoSocket.TimeStamp 
            }
  
            const respuestaString: string = JSON.stringify(respuesta);
            const hash: string = cryptojs.SHA256(respuestaString).toString(); 
            const hashFirmaBigint: bigint = usuarioLista.publicKey.verify(bigintConversion.hexToBigint(recibidoSocket.firma));
            const hashFirma: string = bigintConversion.bigintToHex(hashFirmaBigint);
            if (hashFirma === hash){
              this.recibido = true;
              this.disabled = true;
              this.mensajeNoRepudio = respuesta;
            }
          }
        })
      }
    })

    this.socket.on('contestado', (recibidoSocket: NoRepudio) => {
      this.usuarios.forEach((usuarioLista: Usuario) => {
        if (usuarioLista.nombre === recibidoSocket.usuarioDestino){
          const respuesta: NoRepudio = {
            usuarioOrigen: recibidoSocket.usuarioOrigen,
            usuarioDestino: recibidoSocket.usuarioDestino,
            cifrado: recibidoSocket.cifrado,
            TimeStamp: recibidoSocket.TimeStamp
          }

          if (respuesta.usuarioOrigen === recibidoSocket.usuarioOrigen && respuesta.usuarioDestino === recibidoSocket.usuarioDestino && respuesta.cifrado === recibidoSocket.cifrado){
            const hash: string = cryptojs.SHA256(JSON.stringify(respuesta)).toString();
            const hashFirmaBigint: bigint = usuarioLista.publicKey.verify(bigintConversion.hexToBigint(recibidoSocket.firma));
            const hashFirma: string = bigintConversion.bigintToHex(hashFirmaBigint);
            if (hashFirma === hash){
              this.enviado = false;
              this.contestado = true;

              let enviar: NoRepudio = {
                usuarioOrigen: recibidoSocket.usuarioOrigen,
                usuarioDestino: recibidoSocket.usuarioDestino,
                cifrado: bigintConversion.bufToHex(this.ivNoRepudio),
                TimeStamp: new Date(Date.now()).toString()
              }

              const hash: string = cryptojs.SHA256(JSON.stringify(enviar)).toString();
              const firma: bigint = this.servidorService.firmarRSA(bigintConversion.hexToBigint(hash));
              enviar.firma = bigintConversion.bigintToHex(firma);
              this.servidorService.enviarClave(enviar).subscribe(data => {
                const recibido: NoRepudio = {
                  usuarioOrigen: data.usuarioOrigen,
                  usuarioDestino: data.usuarioDestino,
                  cifrado: data.cifrado,
                  TimeStamp: data.TimeStamp,
                }

                const hash: string = cryptojs.SHA256(JSON.stringify(recibido)).toString();
                const firmaBigint: bigint = this.servidorService.verificarRSA(bigintConversion.hexToBigint(data.firma));
                const firma: string = bigintConversion.bigintToHex(firmaBigint);
                if (firma !== hash){
                  console.log("NO SE HA PODIDO AUTENTICAR AL SERVIDOR")
                }
                
                this.contestado = false;
                this.disabled = false;
                this.mensajeNoRepudio = undefined;
              })
            }
          }
        }
      })
    })

    this.socket.on('clave', async (recibido: NoRepudio) => {
      const respuesta: NoRepudio = {
        usuarioOrigen: recibido.usuarioOrigen,
        usuarioDestino: recibido.usuarioDestino,
        cifrado: recibido.cifrado,
        TimeStamp: recibido.TimeStamp
      }

      const hash: string = cryptojs.SHA256(JSON.stringify(respuesta)).toString();
      const firmaBigint: bigint = this.servidorService.verificarRSA(bigintConversion.hexToBigint(recibido.firma));
      const firma: string = bigintConversion.bigintToHex(firmaBigint);
      if (hash === firma){
        const cifradoAES: CifradoAES = {
          mensaje: new Uint8Array(bigintConversion.hexToBuf(this.mensajeNoRepudio.cifrado)),
          iv: new Uint8Array(bigintConversion.hexToBuf(respuesta.cifrado))
        }

        const descifrado: Uint8Array = await this.servidorService.descifrarAES(cifradoAES);
        const mensaje: Mensaje = {
          usuario: respuesta.usuarioOrigen,
          mensaje: bigintConversion.bufToText(descifrado)
        }
        this.mensajesNoRepudio.push(mensaje);
      }
      
      else{
        console.log("NO SE HA RECIBIDO LA CLAVE");
      }

      this.disabled = false;
      this.mensajeNoRepudio = undefined;
      this.changeDetectorRef.detectChanges();
    })

    this.socket.on('noContestado', () => {
      this.recibido = false;
      this.disabled = false;
      this.mensajeNoRepudio = undefined;
    })

    this.socket.on('recuento', data => {
      if (this.votado === true){
        console.log(data);
        const recuento: string = bigintConversion.hexToBigint(data).toString();
        
        if (recuento.length < 2){
          this.votosMarianoRajoy = recuento;
        }

        else if (recuento.length === 3){
          this.votosMarianoRajoy = recuento.slice(1,3);
          if (this.votosMarianoRajoy[0] === "0")
            this.votosMarianoRajoy = this.votosMarianoRajoy[1];
          this.votosDonaldTrump = recuento[0];
        }

        else if (recuento.length === 4){
          this.votosMarianoRajoy = recuento.slice(2,4);
          if (this.votosMarianoRajoy[0] === "0")
            this.votosMarianoRajoy = this.votosMarianoRajoy[1];
          this.votosDonaldTrump = recuento.slice(0,2);
        }

        else if (recuento.length === 5){
          this.votosMarianoRajoy = recuento.slice(3,5);
          if (this.votosMarianoRajoy[0] === "0")
            this.votosMarianoRajoy = this.votosMarianoRajoy[1];
          this.votosDonaldTrump = recuento.slice(1,3);
          if (this.votosDonaldTrump[0] === "0")
            this.votosDonaldTrump = this.votosDonaldTrump[1];
          this.votosJuanelas = recuento[0];
        }

        else {
          this.votosMarianoRajoy = recuento.slice(4,6);
          if (this.votosMarianoRajoy[0] === "0")
            this.votosMarianoRajoy = this.votosMarianoRajoy[1];
          this.votosDonaldTrump = recuento.slice(2,4);
          if (this.votosDonaldTrump[0] == "0")
            this.votosDonaldTrump = this.votosDonaldTrump[1];
          this.votosJuanelas = recuento.slice(0,2);
        }
      }
    })
  }

  setUsuario(): void {
    if (this.usuarioTextBox === undefined || this.usuarioTextBox === ""){
      this.errorNombre = true;
      return
    }
    
    else{
      this.errorNombre = false;

      if (this.usuario === undefined){
        try {
          const obs = this.servidorService.conectar(this.usuarioTextBox);
          obs.subscribe(data => {
            this.errorElegido = false;
            data.forEach((usuarioLista: UsuarioServidor)  => {
              const nuevoUsuario: Usuario = {
                nombre: usuarioLista.nombre,
                publicKey: new RsaPublicKey (bigintConversion.hexToBigint(usuarioLista.eHex), bigintConversion.hexToBigint(usuarioLista.nHex))
              }
              this.usuarios.push(nuevoUsuario)
            })
            this.usuario = this.usuarioTextBox;
            this.sockets();
            const usuarioEnviar: UsuarioServidor = {
              nombre: this.usuario,
              nHex: bigintConversion.bigintToHex(this.servidorService.getkeyRSAPublica().n),
              eHex: bigintConversion.bigintToHex(this.servidorService.getkeyRSAPublica().e)
            }

            this.socket.emit('nuevoConectado', usuarioEnviar);
          }, () => {
            this.errorElegido = true;
            this.usuarioTextBox = "";
          })
        } catch (error) {
          console.error(error);
        }
        
      }
  
      else{
        const cambioUsuario: string[] = [this.usuario, this.usuarioTextBox];
        this.servidorService.cambiar(cambioUsuario).subscribe(() => {
          this.usuario = this.usuarioTextBox;
          this.socket.emit('cambiarNombre', cambioUsuario);
        }, () => {
          this.errorElegido = true;
          this.usuarioTextBox = this.usuario;
        })
      }
    }
  }

  async enviar(): Promise<void>{
    if (this.cifrado === undefined){
      this.errorCifrado = true;
      this.errorNombre = false;
      return
    }

    if (this.mensaje === undefined || this.mensaje === ""){
      this.errorMensaje = true;
      this.errorNombre = false;

      if (this.cifrado !== undefined)
        this.errorCifrado = false;
      return
    }

    this.errorCifrado = false;
    this.errorMensaje = false;
    this.errorElegido = false;
    this.errorNombre = false;
    this.mensajes.push({
      usuario: "Server",
      mensaje: "Enviando..."
    })

    if (this.cifrado === "Firma Ciega"){
      const hashmensaje: string = cryptojs.SHA256(this.mensaje).toString();
      const hashCegadoBigint: bigint = await this.servidorService.cegarRSA(bigintConversion.hexToBigint(hashmensaje));
      const hashCegado: string = bigintConversion.bigintToHex(hashCegadoBigint);
      const enviar: Mensaje = {
        usuario: this.usuario,
        mensaje: hashCegado
      }

      this.servidorService.firmarServidor(enviar).subscribe(data => {
        const firma: bigint = this.servidorService.descegarRSA(bigintConversion.hexToBigint(data.mensaje));
        const digestBigint: bigint = this.servidorService.verificarRSA(firma);
        const digest: string = bigintConversion.bigintToHex(digestBigint);
        if (digest === hashmensaje){
          const mensaje: Mensaje = {
            usuario: this.usuario,
            mensaje: this.mensaje + "(VERIFICADO)"
          }

          this.mensajes[this.mensajes.length - 1] = mensaje
          this.mensaje = "";
          this.changeDetectorRef.detectChanges();
        }

        else{
          console.log("ERROR")
        }
      })
    }

    else{
      let enviar: MensajeServidor;
      if (this.cifrado === "RSA"){
        const cifrado: CifradoRSA = await this.servidorService.cifrarRSA(new Uint8Array(bigintConversion.textToBuf(this.mensaje)));
        enviar = {
          usuario: this.usuario,
          tipo: "RSA",
          cifrado: bigintConversion.bufToHex(cifrado.cifrado.mensaje),
          iv: bigintConversion.bufToHex(cifrado.cifrado.iv),
          clave: cifrado.clave
        }
      }
      
      this.servidorService.enviarCifrado(enviar).subscribe(async data => {
        const cifradoAES: CifradoAES = {
          mensaje: new Uint8Array(bigintConversion.hexToBuf(data.cifrado)),
          iv: new Uint8Array(bigintConversion.hexToBuf(data.iv))
        }

        const mensaje: Uint8Array = await this.servidorService.descifrarAES(cifradoAES);
        const mensajeRecibido: Mensaje = {
          usuario: data.usuario,
          mensaje: bigintConversion.bufToText(mensaje)
        }

        this.mensajes[this.mensajes.length - 1] = mensajeRecibido
        this.mensaje = "";
        this.changeDetectorRef.detectChanges();
      })
    }
  }




  async votar(): Promise<void> {
    if (this.candidato === undefined){
      this.errorVoto = true;
      return;
    }

    this.votado = true;
    let voto: bigint;
    this.errorVoto = false;
    if (this.candidato === "1")
      voto = 1n;

    else if (this.candidato === "100")
      voto = 100n;

    else
      voto = 10000n;

    const votoCifrado: bigint = await this.servidorService.cifrarVotoRSA(voto);
    this.servidorService.votar(votoCifrado).subscribe(data => {
      const recuento: string = bigintConversion.hexToBigint(data.recuento).toString();

      if (recuento.length < 2){
        this.votosMarianoRajoy = recuento;
      }

      else if (recuento.length === 3){
        this.votosMarianoRajoy = recuento.slice(1,3);
        if (this.votosMarianoRajoy[0] === "0")
          this.votosMarianoRajoy = this.votosMarianoRajoy[1];
        this.votosDonaldTrump = recuento[0];
      }

      else if (recuento.length === 4){
        this.votosMarianoRajoy = recuento.slice(2,4);
        if (this.votosMarianoRajoy[0] === "0")
          this.votosMarianoRajoy = this.votosMarianoRajoy[1];
        this.votosDonaldTrump = recuento.slice(0,2);
      }

      else if (recuento.length === 5){
        this.votosMarianoRajoy = recuento.slice(3,5);
        if (this.votosMarianoRajoy[0] === "0")
          this.votosMarianoRajoy = this.votosMarianoRajoy[1];
        this.votosDonaldTrump = recuento.slice(1,3);
        if (this.votosDonaldTrump[0] === "0")
          this.votosDonaldTrump = this.votosDonaldTrump[1];
        this.votosJuanelas = recuento[0];
      }

      else {
        this.votosMarianoRajoy = recuento.slice(4,6);
        if (this.votosMarianoRajoy[0] === "0")
          this.votosMarianoRajoy = this.votosMarianoRajoy[1];
        this.votosDonaldTrump = recuento.slice(2,4);
        if (this.votosDonaldTrump[0] == "0")
          this.votosDonaldTrump = this.votosDonaldTrump[1];
        this.votosJuanelas = recuento.slice(0,2);
      }

      if (data.mensaje !== undefined){
        this.erroMax = true;
      }
      this.changeDetectorRef.detectChanges();
    })
  }

  getClaves(): void{
    if (this.secreto === undefined || this.secreto === "" || this.shared === undefined || this.shared === 0 || this.threshold === undefined || this.threshold === 0 || this.shared < this.threshold){
      this.errorSecreto = true;
      return;
    }

    this.errorSecreto = false;
    const enviar: secretoCompartido = {
      secreto: this.secreto,
      shared: this.shared,
      threshold: this.threshold
    }

    this.servidorService.getClavesCompartidas(enviar).subscribe(data => {
      this.clavesCompartidas = data;
    })
  }

  setLenClaves(): void {
    if (this.numClaves > 0)
      this.claves.length = this.numClaves;
    
    else
      this.numClaves = 0;
  }

  getSecreto(): void {
    this.errorRecuperado = false;
    this.claves.forEach((clave:string) => {
      if (clave === undefined || clave === ""){
        this.errorClaves = true;
        return;
      }
    })

    this.errorClaves = false;
    this.servidorService.getSecreto(this.claves).subscribe(data => {
      this.secretoRecuperado = data;
      this.changeDetectorRef.detectChanges();
    }, () => {
      this.errorRecuperado = true;
      this.changeDetectorRef.detectChanges();
    })
  }
}





