// ========================================
// THREE.JS SECURITY NETWORK BACKGROUND
// Animated network topology with hex grid
// ========================================

(function () {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas || typeof THREE === 'undefined') return;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
  // Use opaque renderer with the page background color
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setClearColor(0x0a0a14, 1); // Match --bg color exactly

  camera.position.set(0, 0, 30);

  // --- Configuration ---
  const NODE_COUNT = 100;
  const CONNECTION_DISTANCE = 9;
  const PURPLE = new THREE.Color(0x7B2D8E);
  const PURPLE_LIGHT = new THREE.Color(0xC090C0);
  const TEAL = new THREE.Color(0x60A5FA);

  // --- Nodes ---
  const nodePositions = [];
  const nodeVelocities = [];
  const nodeSizes = [];

  for (let i = 0; i < NODE_COUNT; i++) {
    nodePositions.push(
      (Math.random() - 0.5) * 50,
      (Math.random() - 0.5) * 30,
      (Math.random() - 0.5) * 15 - 5
    );
    nodeVelocities.push(
      (Math.random() - 0.5) * 0.01,
      (Math.random() - 0.5) * 0.01,
      (Math.random() - 0.5) * 0.005
    );
    nodeSizes.push(0.15 + Math.random() * 0.25);
  }

  const nodeGeometry = new THREE.BufferGeometry();
  nodeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(nodePositions, 3));
  nodeGeometry.setAttribute('size', new THREE.Float32BufferAttribute(nodeSizes, 1));

  const nodeShaderMaterial = new THREE.ShaderMaterial({
    uniforms: {
      uColor: { value: PURPLE_LIGHT },
      uTime: { value: 0 }
    },
    vertexShader: `
      attribute float size;
      uniform float uTime;
      varying float vAlpha;
      void main() {
        vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
        gl_PointSize = size * (250.0 / -mvPosition.z);
        gl_Position = projectionMatrix * mvPosition;
        vAlpha = 0.4 + 0.3 * sin(uTime * 0.5 + position.x * 0.5);
      }
    `,
    fragmentShader: `
      uniform vec3 uColor;
      varying float vAlpha;
      void main() {
        float d = length(gl_PointCoord - vec2(0.5));
        if (d > 0.5) discard;
        float glow = smoothstep(0.5, 0.05, d);
        gl_FragColor = vec4(uColor, vAlpha * glow);
      }
    `,
    transparent: true,
    depthWrite: false
  });

  const nodesMesh = new THREE.Points(nodeGeometry, nodeShaderMaterial);
  scene.add(nodesMesh);

  // --- Connection lines ---
  const maxLines = NODE_COUNT * 4;
  const linePositions = new Float32Array(maxLines * 6);
  const lineColors = new Float32Array(maxLines * 6);
  const lineGeometry = new THREE.BufferGeometry();
  lineGeometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
  lineGeometry.setAttribute('color', new THREE.Float32BufferAttribute(lineColors, 3));

  const lineMaterial = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: 0.6,
    depthWrite: false
  });

  const linesMesh = new THREE.LineSegments(lineGeometry, lineMaterial);
  scene.add(linesMesh);

  // --- Hex grid (background pattern) ---
  const hexGroup = new THREE.Group();
  const hexMaterial = new THREE.LineBasicMaterial({
    color: PURPLE,
    transparent: true,
    opacity: 0.12
  });

  for (let row = -6; row <= 6; row++) {
    for (let col = -10; col <= 10; col++) {
      const x = col * 4 + (row % 2) * 2;
      const y = row * 3.5;
      const hexShape = new THREE.BufferGeometry();
      const verts = [];
      for (let i = 0; i <= 6; i++) {
        const angle = (Math.PI / 3) * i - Math.PI / 6;
        verts.push(x + 1.8 * Math.cos(angle), y + 1.8 * Math.sin(angle), -15);
      }
      hexShape.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3));
      hexGroup.add(new THREE.Line(hexShape, hexMaterial));
    }
  }
  scene.add(hexGroup);

  // --- Water-drop ripples (thin expanding circles) ---
  // 4 severity-themed colors
  const RIPPLE_COLORS = [
    new THREE.Color(0xC090C0), // Purple — info / default
    new THREE.Color(0xEF4444), // Red — critical / high alert
    new THREE.Color(0xF59E0B), // Amber/Yellow — medium alert
    new THREE.Color(0x22D3EE), // Cyan/Teal — low / informational
  ];

  const pulseRings = [];
  const RING_INTERVAL = 3000;
  let lastRingTime = 0;

  function createRipple() {
    const x = (Math.random() - 0.5) * 35;
    const y = (Math.random() - 0.5) * 20;
    // Pick a random severity color for this ripple cluster
    const color = RIPPLE_COLORS[Math.floor(Math.random() * RIPPLE_COLORS.length)];
    // Spawn 3 concentric ripples with staggered delays
    for (let r = 0; r < 3; r++) {
      const curve = new THREE.EllipseCurve(0, 0, 1, 1, 0, Math.PI * 2, false, 0);
      const points = curve.getPoints(64);
      const geom = new THREE.BufferGeometry().setFromPoints(points);
      const mat = new THREE.LineBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.35
      });
      const ring = new THREE.LineLoop(geom, mat);
      ring.position.set(x, y, -1);
      ring.scale.set(0.1, 0.1, 1);
      ring.userData = { age: -r * 0.4, maxAge: 4.0 }; // staggered start
      scene.add(ring);
      pulseRings.push(ring);
    }
  }

  // --- Data stream particles (falling green "data") ---
  const STREAM_COUNT = 60;
  const streamPositions = [];
  const streamVelocities = [];
  for (let i = 0; i < STREAM_COUNT; i++) {
    streamPositions.push(
      (Math.random() - 0.5) * 55,
      25 + Math.random() * 15,
      (Math.random() - 0.5) * 10 - 3
    );
    streamVelocities.push(0, -(0.03 + Math.random() * 0.05), 0);
  }

  const streamGeometry = new THREE.BufferGeometry();
  streamGeometry.setAttribute('position', new THREE.Float32BufferAttribute(streamPositions, 3));

  const streamMaterial = new THREE.ShaderMaterial({
    uniforms: {
      uColor: { value: new THREE.Color(0x4ADE80) },
      uTime: { value: 0 }
    },
    vertexShader: `
      uniform float uTime;
      varying float vAlpha;
      void main() {
        vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
        gl_PointSize = 2.5 * (200.0 / -mvPosition.z);
        gl_Position = projectionMatrix * mvPosition;
        vAlpha = 0.3 + 0.2 * sin(uTime * 2.0 + position.x);
      }
    `,
    fragmentShader: `
      uniform vec3 uColor;
      varying float vAlpha;
      void main() {
        float d = length(gl_PointCoord - vec2(0.5));
        if (d > 0.5) discard;
        gl_FragColor = vec4(uColor, vAlpha * smoothstep(0.5, 0.0, d));
      }
    `,
    transparent: true,
    depthWrite: false
  });

  const streamMesh = new THREE.Points(streamGeometry, streamMaterial);
  scene.add(streamMesh);

  // --- Animation loop ---
  const clock = new THREE.Clock();

  function animate() {
    requestAnimationFrame(animate);
    const elapsed = clock.getElapsedTime();

    // Update node positions
    const pos = nodeGeometry.attributes.position.array;
    for (let i = 0; i < NODE_COUNT; i++) {
      const i3 = i * 3;
      pos[i3] += nodeVelocities[i3];
      pos[i3 + 1] += nodeVelocities[i3 + 1];
      pos[i3 + 2] += nodeVelocities[i3 + 2];

      if (Math.abs(pos[i3]) > 25) nodeVelocities[i3] *= -1;
      if (Math.abs(pos[i3 + 1]) > 15) nodeVelocities[i3 + 1] *= -1;
      if (Math.abs(pos[i3 + 2] + 5) > 8) nodeVelocities[i3 + 2] *= -1;
    }
    nodeGeometry.attributes.position.needsUpdate = true;
    nodeShaderMaterial.uniforms.uTime.value = elapsed;

    // Update connections
    let lineIdx = 0;
    const lp = lineGeometry.attributes.position.array;
    const lc = lineGeometry.attributes.color.array;
    for (let i = 0; i < NODE_COUNT && lineIdx < maxLines; i++) {
      for (let j = i + 1; j < NODE_COUNT && lineIdx < maxLines; j++) {
        const i3 = i * 3, j3 = j * 3;
        const dx = pos[i3] - pos[j3];
        const dy = pos[i3 + 1] - pos[j3 + 1];
        const dz = pos[i3 + 2] - pos[j3 + 2];
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

        if (dist < CONNECTION_DISTANCE) {
          const idx = lineIdx * 6;
          lp[idx] = pos[i3]; lp[idx + 1] = pos[i3 + 1]; lp[idx + 2] = pos[i3 + 2];
          lp[idx + 3] = pos[j3]; lp[idx + 4] = pos[j3 + 1]; lp[idx + 5] = pos[j3 + 2];

          const alpha = 1 - dist / CONNECTION_DISTANCE;
          // Purple connection color
          lc[idx] = 0.48 * alpha; lc[idx + 1] = 0.18 * alpha; lc[idx + 2] = 0.56 * alpha;
          lc[idx + 3] = 0.48 * alpha; lc[idx + 4] = 0.18 * alpha; lc[idx + 5] = 0.56 * alpha;
          lineIdx++;
        }
      }
    }
    // Clear remaining
    for (let i = lineIdx; i < maxLines; i++) {
      const idx = i * 6;
      lp[idx] = lp[idx + 1] = lp[idx + 2] = 0;
      lp[idx + 3] = lp[idx + 4] = lp[idx + 5] = 0;
    }
    lineGeometry.attributes.position.needsUpdate = true;
    lineGeometry.attributes.color.needsUpdate = true;
    lineGeometry.setDrawRange(0, lineIdx * 2);

    // Water-drop ripples
    const now = performance.now();
    if (now - lastRingTime > RING_INTERVAL) {
      createRipple();
      lastRingTime = now;
    }

    for (let i = pulseRings.length - 1; i >= 0; i--) {
      const ring = pulseRings[i];
      ring.userData.age += 0.016;
      const age = ring.userData.age;
      if (age < 0) continue; // staggered delay
      const t = age / ring.userData.maxAge;
      if (t >= 1) {
        scene.remove(ring);
        ring.geometry.dispose();
        ring.material.dispose();
        pulseRings.splice(i, 1);
        continue;
      }
      // Expand like a water droplet — fast start, slowing down
      const ease = 1 - Math.pow(1 - t, 2);
      const scale = 0.2 + ease * 10;
      ring.scale.set(scale, scale, 1);
      // Fade out smoothly
      ring.material.opacity = 0.3 * (1 - t);
    }

    // Data streams
    const sp = streamGeometry.attributes.position.array;
    for (let i = 0; i < STREAM_COUNT; i++) {
      const i3 = i * 3;
      sp[i3 + 1] += streamVelocities[i3 + 1];
      if (sp[i3 + 1] < -20) {
        sp[i3] = (Math.random() - 0.5) * 55;
        sp[i3 + 1] = 20 + Math.random() * 15;
      }
    }
    streamGeometry.attributes.position.needsUpdate = true;
    streamMaterial.uniforms.uTime.value = elapsed;

    // Gentle hex rotation
    hexGroup.rotation.z = Math.sin(elapsed * 0.05) * 0.03;

    // Subtle camera sway
    camera.position.x = Math.sin(elapsed * 0.1) * 0.8;
    camera.position.y = Math.cos(elapsed * 0.08) * 0.5;

    renderer.render(scene, camera);
  }

  animate();

  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });
})();
