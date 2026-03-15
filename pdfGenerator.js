
const PDFDocument = require('pdfkit');
const https = require('https');
const http = require('http');

class PDFGenerator {
  static async generarReporteNino(ninoData) {
    return new Promise(async (resolve, reject) => {
      try {
        console.log('Iniciando generación de PDF...');
        console.log('Datos del niño:', ninoData.nino?.nombres_nino);
        
        const doc = new PDFDocument({ 
          margin: 50,
          size: 'LETTER',
          info: {
            Title: `Reporte Tamizaje - ${ninoData.nino?.nombres_nino || 'Paciente'}`,
            Author: 'Sistema de Tamizaje Visual Infantil',
            Subject: 'Reporte Médico de Tamizaje Visual'
          }
        });
        
        const buffers = [];

        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => {
          console.log('PDF generado correctamente');
          const pdfData = Buffer.concat(buffers);
          resolve(pdfData);
        });

        doc.on('error', (error) => {
          console.error('Error en el stream del PDF:', error);
          reject(error);
        });

        // configuracion del documento
        console.log('Agregando header...');
        await this._agregarHeader(doc, ninoData.nino);
        
        console.log('Agregando datos del niño...');
        this._agregarDatosNino(doc, ninoData.nino);
        
        if (ninoData.tutores && ninoData.tutores.length > 0) {
          console.log('Agregando datos del tutor...');
          this._agregarDatosTutor(doc, ninoData.tutores[0]);
        }

        if (ninoData.tamizajes && ninoData.tamizajes.length > 0) {
          console.log('Agregando tamizajes...');
          this._agregarTamizajes(doc, ninoData.tamizajes);
        }

        if (ninoData.nino?.observaciones) {
          console.log('Agregando observaciones...');
          this._agregarObservaciones(doc, ninoData.nino.observaciones);
        }

        console.log('Agregando footer...');
        this._agregarFooter(doc);
        
        doc.end();

      } catch (error) {
        console.error('Error crítico generando PDF:', error);
        console.error('Stack:', error.stack);
        reject(error);
      }
    });
  }

  static async _agregarHeader(doc, nino) {
    try {
      // Rectangulo superior con color
      doc
        .rect(0, 0, 612, 80)
        .fillColor('#4A90E2')
        .fill();

      // titulo principal
      doc
        .fontSize(24)
        .font('Helvetica-Bold')
        .fillColor('#FFFFFF')
        .text('REPORTE MÉDICO', 50, 20, { align: 'center' })
        .fontSize(16)
        .text('TAMIZAJE VISUAL INFANTIL', 50, 48, { align: 'center' });

      // Informacion de generacion
      doc
        .fontSize(9)
        .font('Helvetica')
        .fillColor('#666666')
        .text(`Fecha de generación: ${this._formatearFechaCompleta(new Date())}`, 50, 90, { align: 'right' })
        .text(`Hora: ${new Date().toLocaleTimeString('es-ES')}`, 50, 102, { align: 'right' });


      doc.y = 120;

      // Intentar cargar imagen del niño si existe
      if (nino?.url_imagen && nino.url_imagen.trim() !== '') {
        console.log('Intentando cargar imagen:', nino.url_imagen);
        try {
          const imageBuffer = await this._descargarImagen(nino.url_imagen);
          

          const photoX = 450;
          const photoY = 120;
          const photoSize = 100;
          
          // Marco para la foto
          doc
            .rect(photoX - 5, photoY - 5, photoSize + 10, photoSize + 10)
            .strokeColor('#4A90E2')
            .lineWidth(2)
            .stroke();

          // Insertar imagen
          doc.image(imageBuffer, photoX, photoY, {
            width: photoSize,
            height: photoSize,
            align: 'center',
            valign: 'center'
          });

          doc
            .fontSize(8)
            .font('Helvetica')
            .fillColor('#666666')
            .text('FOTOGRAFÍA', photoX, photoY + photoSize + 8, { width: photoSize, align: 'center' });

          console.log('Imagen cargada correctamente');
        } catch (error) {
          console.log('No se pudo cargar la imagen:', error.message);
        }
      } else {
        console.log('No hay URL de imagen');
      }

      doc.y = 240;
      doc
        .moveTo(50, doc.y)
        .lineTo(562, doc.y)
        .strokeColor('#4A90E2')
        .lineWidth(2)
        .stroke();
      
      doc.y = 250;
      doc.moveDown(0.5);
    } catch (error) {
      console.error('Error en _agregarHeader:', error);
      throw error;
    }
  }

  static _descargarImagen(url) {
    return new Promise((resolve, reject) => {
      const protocol = url.startsWith('https') ? https : http;
      
      const request = protocol.get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`Error descargando imagen: ${response.statusCode}`));
          return;
        }

        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve(Buffer.concat(chunks)));
      });

      request.on('error', (error) => reject(error));
      request.setTimeout(5000, () => {
        request.destroy();
        reject(new Error('Timeout descargando imagen'));
      });
    });
  }

  static _agregarDatosNino(doc, nino) {
    try {
      this._agregarTituloSeccion(doc, 'DATOS DEL PACIENTE');

      const edad = this._calcularEdad(nino?.fecha_nacimiento);

      const datosNino = [
        { 
          label: 'Nombres Completos:', 
          valor: `${nino?.nombres_nino || ''} ${nino?.paterno_nino || ''} ${nino?.materno_nino || ''}`.trim() || 'No especificado' 
        },
        { label: 'Carnet de Identidad:', valor: nino?.carnet_nino || 'No especificado' },
        { label: 'Fecha de Nacimiento:', valor: this._formatearFecha(nino?.fecha_nacimiento) },
        { label: 'Edad:', valor: edad },
        { 
          label: 'Género:', 
          valor: nino?.genero === 'M' ? 'Masculino' : nino?.genero === 'F' ? 'Femenino' : 'No especificado' 
        },
        { label: 'Fecha de Registro:', valor: this._formatearFecha(nino?.fecha_registro) }
      ];

      this._agregarTablaDatos(doc, datosNino);
      doc.moveDown(1);
    } catch (error) {
      console.error('Error en _agregarDatosNino:', error);
      throw error;
    }
  }

  static _agregarDatosTutor(doc, tutor) {
    try {
      this._agregarTituloSeccion(doc, 'DATOS DEL TUTOR/RESPONSABLE');

      const datosTutor = [
        { 
          label: 'Nombre Completo:', 
          valor: `${tutor?.nombre_tutor || ''} ${tutor?.paterno_tutor || ''} ${tutor?.materno_tutor || ''}`.trim() || 'No especificado' 
        },
        { label: 'Carnet de Identidad:', valor: tutor?.carnet_tutor || 'No especificado' },
        { label: 'Parentesco:', valor: tutor?.parentesco || 'No especificado' },
        { label: 'Teléfono Celular:', valor: tutor?.celular || 'No especificado' },
        { label: 'Correo Electrónico:', valor: tutor?.email || 'No especificado' },
        { label: 'Tutor Principal:', valor: tutor?.es_tutor_principal ? 'Sí' : 'No' }
      ];

      this._agregarTablaDatos(doc, datosTutor);
      doc.moveDown(1);
    } catch (error) {
      console.error('Error en _agregarDatosTutor:', error);
      throw error;
    }
  }

  static _agregarTamizajes(doc, tamizajes) {
    try {
      this._agregarTituloSeccion(doc, 'RESULTADOS DEL TAMIZAJE VISUAL');

      const tamizajeOD = tamizajes.find(t => t.ojo === 'DERECHO');
      const tamizajeOI = tamizajes.find(t => t.ojo === 'IZQUIERDO');

      if (tamizajeOD) {
        console.log('Agregando tamizaje OD...');
        this._agregarTamizajeDetallado(doc, tamizajeOD, 'OJO DERECHO (OD)');
      }

      if (tamizajeOI) {
        console.log('Agregando tamizaje OI...');
        this._agregarTamizajeDetallado(doc, tamizajeOI, 'OJO IZQUIERDO (OI)');
      }
    } catch (error) {
      console.error('Error en _agregarTamizajes:', error);
      throw error;
    }
  }

  static _agregarTamizajeDetallado(doc, tamizaje, titulo) {
    try {

      if (doc.y > 620) {
        doc.addPage();
        doc.y = 50;
      }


      const tituloY = doc.y;


      doc
        .rect(50, tituloY, 512, 25)
        .fillColor('#28a745')
        .fill();

      doc
        .fontSize(14)
        .font('Helvetica-Bold')
        .fillColor('#FFFFFF')
        .text(titulo, 55, tituloY + 6, { align: 'left' });


      doc.y = tituloY + 25;
      doc.moveDown(0.8);

      const datosGenerales = [
        { label: 'Fecha del Examen:', valor: this._formatearFechaCompleta(tamizaje.fecha) },
        { label: 'Estado del Examen:', valor: this._formatearEstado(tamizaje.estado) },
        { 
          label: 'Niveles Superados:', 
          valor: tamizaje.niveles_superados !== null ? `${tamizaje.niveles_superados} niveles` : 'No registrado' 
        },
        { 
          label: 'Aciertos Totales:', 
          valor: tamizaje.aciertos_totales !== null ? `${tamizaje.aciertos_totales} aciertos` : 'No registrado' 
        }
      ];

      this._agregarTablaDatos(doc, datosGenerales);

      doc.moveDown(0.5);
      doc
        .fontSize(12)
        .font('Helvetica-Bold')
        .fillColor('#4A90E2')
        .text('MÉTRICAS DE RENDIMIENTO', 50);
      
      doc.moveDown(0.3);

      const metricas = [
        { 
          label: 'Porcentaje de Aciertos:', 
          valor: tamizaje.porcentaje_aciertos !== null ? `${tamizaje.porcentaje_aciertos}%` : 'No registrado',
          destacar: true 
        },
        { 
          label: 'Tiempo Promedio de Respuesta:', 
          valor: tamizaje.tiempo_promedio !== null ? `${parseFloat(tamizaje.tiempo_promedio).toFixed(3)} segundos` : 'No registrado' 
        },
        { label: 'Consistencia:', valor: tamizaje.consistencia || 'No registrado' }
      ];

      this._agregarTablaDatos(doc, metricas);

      if (tamizaje.error_vertical !== null || tamizaje.error_horizontal !== null) {
        doc.moveDown(0.5);
        doc
          .fontSize(12)
          .font('Helvetica-Bold')
          .fillColor('#4A90E2')
          .text('ANÁLISIS DE ERRORES', 50);
        
        doc.moveDown(0.3);

        const errores = [
          { label: 'Error Vertical:', valor: tamizaje.error_vertical !== null ? `${tamizaje.error_vertical}` : 'No registrado' },
          { label: 'Error Horizontal:', valor: tamizaje.error_horizontal !== null ? `${tamizaje.error_horizontal}` : 'No registrado' }
        ];

        this._agregarTablaDatos(doc, errores);
      }

      if (tamizaje.diagnostico_preliminar && tamizaje.diagnostico_preliminar.trim() !== '') {
        if (doc.y > 620) {
          doc.addPage();
          doc.y = 50;
        }

        doc.moveDown(0.5);
        
        doc
          .fontSize(12)
          .font('Helvetica-Bold')
          .fillColor('#4A90E2')
          .text('DIAGNÓSTICO PRELIMINAR', 50);
        
        doc.moveDown(0.3);

        const diagnosticoY = doc.y;
        const diagnosticoHeight = this._calcularAlturaDiagnostico(doc, tamizaje.diagnostico_preliminar);
        
        doc
          .rect(50, diagnosticoY, 512, diagnosticoHeight + 20)
          .fillColor('#FFF9E6')
          .fill()
          .strokeColor('#FFC107')
          .lineWidth(1)
          .stroke();

        doc
          .fontSize(10)
          .font('Helvetica')
          .fillColor('#333333')
          .text(tamizaje.diagnostico_preliminar, 60, diagnosticoY + 10, {
            width: 492,
            align: 'justify',
            lineGap: 2
          });

        doc.y = diagnosticoY + diagnosticoHeight + 25;
      }

      doc.moveDown(0.8);

      if (doc.y < 650) {
        doc
          .moveTo(50, doc.y)
          .lineTo(562, doc.y)
          .strokeColor('#E1E5E9')
          .lineWidth(0.5)
          .stroke()
          .moveDown(0.8);
      }
    } catch (error) {
      console.error('Error en _agregarTamizajeDetallado:', error);
      throw error;
    }
  }

  static _agregarObservaciones(doc, observaciones) {
    try {
      if (!observaciones || observaciones.trim() === '') return;

      if (doc.y > 600) {
        doc.addPage();
        doc.y = 50;
      }

      this._agregarTituloSeccion(doc, 'OBSERVACIONES GENERALES');

      const obsHeight = this._calcularAlturaDiagnostico(doc, observaciones);
      const obsY = doc.y;
      
      doc
        .rect(50, obsY, 512, obsHeight + 20)
        .fillColor('#F0F8FF')
        .fill()
        .strokeColor('#4A90E2')
        .lineWidth(1)
        .stroke();

      doc
        .fontSize(10)
        .font('Helvetica')
        .fillColor('#333333')
        .text(observaciones, 60, obsY + 10, {
          width: 492,
          align: 'justify',
          lineGap: 2
        });

      doc.y = obsY + obsHeight + 30;
    } catch (error) {
      console.error('Error en _agregarObservaciones:', error);
      throw error;
    }
  }

  static _calcularAlturaDiagnostico(doc, texto) {
    try {
      const lines = texto.split('\n').length;
      const charsPerLine = Math.floor(492 / 6);
      const totalLines = Math.ceil(texto.length / charsPerLine) + lines;
      return Math.max(totalLines * 12, 50);
    } catch (error) {
      return 100;
    }
  }

  static _agregarTituloSeccion(doc, titulo) {
    try {
      if (doc.y > 680) {
        doc.addPage();
      }

      const tituloY = doc.y;

      doc
        .rect(50, tituloY, 512, 25)
        .fillColor('#4A90E2')
        .fill();

      doc
        .fontSize(14)
        .font('Helvetica-Bold')
        .fillColor('#FFFFFF')
        .text(titulo, 55, tituloY + 6, { align: 'left' });

      doc.y = tituloY + 25;
      doc.moveDown(0.8);
    } catch (error) {
      console.error('Error en _agregarTituloSeccion:', error);
      throw error;
    }
  }

  static _agregarTablaDatos(doc, datos) {
    try {
      const startY = doc.y;
      const col1Width = 180;
      const col2Width = 332;
      const rowHeight = 22;

      datos.forEach((dato, index) => {
        const y = startY + (index * rowHeight);

        if (y > 700) {
          doc.addPage();
          doc.y = 50;
          return;
        }

        if (index % 2 === 0) {
          doc
            .rect(50, y - 2, 512, rowHeight)
            .fillColor('#F8F9FA')
            .fill();
        }

        doc
          .fontSize(10)
          .font('Helvetica-Bold')
          .fillColor('#495057')
          .text(dato.label, 55, y + 4, { width: col1Width, align: 'left' });

        if (dato.destacar) {
          doc
            .fontSize(11)
            .font('Helvetica-Bold')
            .fillColor('#28a745');
        } else {
          doc
            .fontSize(10)
            .font('Helvetica')
            .fillColor('#333333');
        }

        doc.text(dato.valor, 55 + col1Width, y + 4, { width: col2Width, align: 'left' });
      });

      doc.y = startY + (datos.length * rowHeight);
    } catch (error) {
      console.error('Error en _agregarTablaDatos:', error);
      throw error;
    }
  }

  static _agregarFooter(doc) {
    try {
      const range = doc.bufferedPageRange();
      const pageCount = range.count;
      
      console.log(`Total de páginas: ${pageCount}`);
      

      for (let i = 0; i < pageCount; i++) {
        const pageIndex = range.start + i;
        doc.switchToPage(pageIndex);
        
        if (doc.y < 200 && i > 0) {
          console.log(`Página ${i + 1} parece estar vacía, omitiendo...`);
          continue;
        }
        
        const footerY = 720;

        doc
          .moveTo(50, footerY)
          .lineTo(562, footerY)
          .strokeColor('#4A90E2')
          .lineWidth(1)
          .stroke();

        doc
          .fontSize(8)
          .font('Helvetica')
          .fillColor('#666666')
          .text(
            'CONFIDENCIAL - Uso exclusivo para fines médicos', 
            50, footerY + 10, 
            { align: 'center', width: 512 }
          )
      }
      
      console.log('Footer agregado a todas las páginas con contenido');
    } catch (error) {
      console.error('Error en _agregarFooter:', error);
      console.error('Detalles:', error.message);
      console.log('Continuando sin footer completo...');
    }
  }

  static _formatearFecha(fecha) {
    if (!fecha) return 'No especificada';
    try {
      const d = new Date(fecha);
      const opciones = { year: 'numeric', month: '2-digit', day: '2-digit' };
      return d.toLocaleDateString('es-ES', opciones);
    } catch (error) {
      return 'Fecha inválida';
    }
  }

  static _formatearFechaCompleta(fecha) {
    if (!fecha) return 'No especificada';
    try {
      const d = new Date(fecha);
      const opciones = { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        weekday: 'long'
      };
      return d.toLocaleDateString('es-ES', opciones);
    } catch (error) {
      return 'Fecha inválida';
    }
  }

  static _formatearEstado(estado) {
    const estados = {
      'completado': 'Completado',
      'en_progreso': 'En Progreso',
      'cancelado': 'Cancelado'
    };
    return estados[estado] || estado || 'No especificado';
  }

  static _calcularEdad(fechaNacimiento) {
    if (!fechaNacimiento) return 'No especificada';
    
    try {
      const hoy = new Date();
      const nacimiento = new Date(fechaNacimiento);
      let edad = hoy.getFullYear() - nacimiento.getFullYear();
      const mes = hoy.getMonth() - nacimiento.getMonth();
      
      if (mes < 0 || (mes === 0 && hoy.getDate() < nacimiento.getDate())) {
        edad--;
      }
      
      let meses = mes;
      if (meses < 0) {
        meses += 12;
      }
      
      if (edad === 0) {
        return `${meses} meses`;
      } else if (meses === 0) {
        return `${edad} año${edad !== 1 ? 's' : ''}`;
      } else {
        return `${edad} año${edad !== 1 ? 's' : ''} y ${meses} mes${meses !== 1 ? 'es' : ''}`;
      }
    } catch (error) {
      return 'Edad no calculable';
    }
  }
}

module.exports = PDFGenerator;