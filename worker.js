export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Helper de autenticación contra D1
    async function getAuthUser() {
      const auth = request.headers.get('Authorization') || '';
      if (!auth.startsWith('Bearer ')) return null;
      try {
        const [u, p] = atob(auth.slice(7)).split(':');
        return await env.DB.prepare(
          'SELECT id, usuario, rol FROM usuarios_facturas WHERE usuario = ? AND password = ?'
        ).bind(u, p).first();
      } catch { return null; }
    }

    // 1. Login
    if (path === '/api/login' && request.method === 'POST') {
      const { usuario, password } = await request.json();
      const user = await env.DB.prepare(
        'SELECT id, usuario, rol FROM usuarios_facturas WHERE usuario = ? AND password = ?'
      ).bind(usuario, password).first();
      if (!user) return Response.json({ error: 'Usuario o contraseña incorrectos' }, { status: 401 });
      return Response.json({ ok: true, token: btoa(`${usuario}:${password}`), usuario: user.usuario, rol: user.rol });
    }

    // 2. Listar facturas (solo usuarios logueados)
    if (path === '/api/facturas' && request.method === 'GET') {
      const user = await getAuthUser();
      if (!user) return Response.json({ error: 'No autorizado' }, { status: 401 });
      const { results } = await env.DB.prepare(
        'SELECT * FROM facturas_firmas ORDER BY fecha_creacion DESC LIMIT 100'
      ).all();
      return Response.json(results);
    }

    // 3. Subir PDF original (solo usuarios logueados)
    if (path === '/api/upload' && request.method === 'POST') {
      const user = await getAuthUser();
      if (!user) return Response.json({ error: 'No autorizado' }, { status: 401 });
      const form = await request.formData();
      const file = form.get('pdf');
      const referencia = form.get('referencia') || '';
      if (!file) return Response.json({ error: 'Falta el PDF' }, { status: 400 });

      const id = Math.random().toString(36).substring(2, 8);
      const r2Key = `orig_${id}.pdf`;
      await env.BUCKET.put(r2Key, file.stream(), { httpMetadata: { contentType: 'application/pdf' } });

      await env.DB.prepare(
        'INSERT INTO facturas_firmas (id, nombre_archivo, referencia, creado_por, r2_original) VALUES (?, ?, ?, ?, ?)'
      ).bind(id, file.name, referencia, user.usuario, r2Key).run();

      return Response.json({ ok: true, id });
    }

    // 4. Crear usuario exclusivo (solo admin)
    if (path === '/api/usuarios' && request.method === 'POST') {
      const user = await getAuthUser();
      if (!user || user.rol !== 'admin') return Response.json({ error: 'Solo admin' }, { status: 403 });
      const { usuario, password } = await request.json();
      try {
        await env.DB.prepare(
          "INSERT INTO usuarios_facturas (usuario, password, rol) VALUES (?, ?, 'operador')"
        ).bind(usuario.trim(), password.trim()).run();
        return Response.json({ ok: true });
      } catch {
        return Response.json({ error: 'Ese usuario ya existe' }, { status: 400 });
      }
    }

    // 5. Info pública de una factura (para el chofer)
    if (path.startsWith('/api/factura/') && request.method === 'GET') {
      const id = path.split('/').pop();
      const row = await env.DB.prepare(
        'SELECT id, nombre_archivo, referencia, estado FROM facturas_firmas WHERE id = ?'
      ).bind(id).first();
      if (!row) return Response.json({ error: 'Factura no encontrada' }, { status: 404 });
      return Response.json(row);
    }

    // 6. Descargar PDF desde R2 (original para chofer o firmado para imprimir)
    if (path.startsWith('/api/pdf/') && request.method === 'GET') {
      const id = path.split('/').pop();
      const tipo = url.searchParams.get('tipo') || 'orig';
      const row = await env.DB.prepare('SELECT * FROM facturas_firmas WHERE id = ?').bind(id).first();
      if (!row) return new Response('No encontrado', { status: 404 });

      const key = tipo === 'firmado' ? row.r2_firmado : row.r2_original;
      if (!key) return new Response('Archivo no disponible', { status: 404 });

      const obj = await env.BUCKET.get(key);
      if (!obj) return new Response('Archivo no encontrado en R2', { status: 404 });

      return new Response(obj.body, {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `inline; filename="${tipo === 'firmado' ? 'FIRMADO_' : ''}${row.nombre_archivo}"`
        }
      });
    }

    // 7. Guardar PDF firmado por el chofer
    if (path.startsWith('/api/firmar/') && request.method === 'POST') {
      const id = path.split('/').pop();
      const row = await env.DB.prepare('SELECT * FROM facturas_firmas WHERE id = ?').bind(id).first();
      if (!row) return Response.json({ error: 'No encontrado' }, { status: 404 });
      if (row.estado === 'FIRMADO') return Response.json({ error: 'Esta factura ya fue firmada' }, { status: 400 });

      const pdfBuffer = await request.arrayBuffer();
      const r2Firmado = `firmado_${id}.pdf`;
      await env.BUCKET.put(r2Firmado, pdfBuffer, { httpMetadata: { contentType: 'application/pdf' } });

      await env.DB.prepare(
        "UPDATE facturas_firmas SET estado = 'FIRMADO', fecha_firma = datetime('now', '-3 hours'), r2_firmado = ? WHERE id = ?"
      ).bind(r2Firmado, id).run();

      return Response.json({ ok: true });
    }

    // Resto de rutas: servir public/index.html
    return env.ASSETS.fetch(request);
  }
};
