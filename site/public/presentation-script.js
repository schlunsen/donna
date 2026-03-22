  // ========================================
  // NAVIGATION
  // ========================================

  const slides = document.querySelectorAll('.slide');
  const dots = document.querySelectorAll('.dot');
  const counter = document.getElementById('slide-counter');
  const prevBtn = document.getElementById('nav-prev');
  const nextBtn = document.getElementById('nav-next');

  let currentSlide = 0;
  const totalSlides = slides.length;
  let isTransitioning = false;

  function goToSlide(index, direction = 'next') {
    if (index < 0 || index >= totalSlides || index === currentSlide || isTransitioning) return;
    isTransitioning = true;

    const current = slides[currentSlide];
    const next = slides[index];

    current.classList.remove('slide-active', 'slide-exit-left');
    next.classList.remove('slide-active', 'slide-exit-left');

    if (direction === 'next') {
      next.style.transform = 'translateX(60px)';
      next.style.opacity = '0';
      current.classList.add('slide-exit-left');
    } else {
      next.style.transform = 'translateX(-60px)';
      next.style.opacity = '0';
      current.style.transform = 'translateX(60px)';
      current.style.opacity = '0';
    }

    current.classList.remove('slide-active');
    void next.offsetWidth; // Force reflow

    next.style.transform = '';
    next.style.opacity = '';
    next.classList.add('slide-active');

    dots[currentSlide].classList.remove('active');
    dots[index].classList.add('active');
    counter.textContent = `${index + 1} / ${totalSlides}`;

    currentSlide = index;
    triggerSlideAnimations(index);

    // Play narration audio for this slide
    if (typeof window.__playSlideAudio === 'function') {
      window.__playSlideAudio(index);
    }

    setTimeout(() => {
      isTransitioning = false;
      current.classList.remove('slide-exit-left');
      current.style.transform = '';
      current.style.opacity = '';
    }, 650);
  }

  function nextSlide() {
    if (currentSlide < totalSlides - 1) goToSlide(currentSlide + 1, 'next');
  }

  function prevSlide() {
    if (currentSlide > 0) goToSlide(currentSlide - 1, 'prev');
  }

  // Keyboard
  document.addEventListener('keydown', (e) => {
    switch (e.key) {
      case 'ArrowRight': case 'ArrowDown': case ' ':
        e.preventDefault(); nextSlide(); break;
      case 'ArrowLeft': case 'ArrowUp':
        e.preventDefault(); prevSlide(); break;
    }
  });

  nextBtn.addEventListener('click', nextSlide);
  prevBtn.addEventListener('click', prevSlide);

  dots.forEach((dot, i) => {
    dot.addEventListener('click', () => {
      const dir = i > currentSlide ? 'next' : 'prev';
      goToSlide(i, dir);
    });
  });

  // Touch / swipe
  let touchStartX = 0;
  let touchStartY = 0;

  document.addEventListener('touchstart', (e) => {
    touchStartX = e.touches[0].clientX;
    touchStartY = e.touches[0].clientY;
  }, { passive: true });

  document.addEventListener('touchend', (e) => {
    const deltaX = e.changedTouches[0].clientX - touchStartX;
    const deltaY = e.changedTouches[0].clientY - touchStartY;
    if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 50) {
      if (deltaX < 0) nextSlide(); else prevSlide();
    }
  }, { passive: true });

  // ========================================
  // SLIDE ANIMATIONS
  // ========================================

  function triggerSlideAnimations(index) {
    const slide = slides[index];

    // Slide 2 (index 1): Philosophy points
    if (index === 1) {
      slide.querySelectorAll('.philosophy-point').forEach((point, i) => {
        setTimeout(() => point.classList.add('visible'), 400 + i * 300);
      });
    }

    // Slide 4 (index 3): Meet Donna — phased intro animation
    if (index === 3) {
      // Reset any previous state
      slide.classList.remove('phase-intro', 'phase-settled');
      slide.querySelectorAll('.agent-orbital').forEach(n => n.classList.remove('visible'));

      // Phase 1: Show "Meet Donna" centered with beaming glow (0s)
      slide.classList.add('phase-intro');

      // Phase 2: After 4s, move title up and reveal subtitle + constellation
      setTimeout(() => {
        slide.classList.remove('phase-intro');
        slide.classList.add('phase-settled');

        // Phase 3: After constellation fades in, show agents one by one with 2s delay
        slide.querySelectorAll('.agent-orbital').forEach((node, i) => {
          setTimeout(() => node.classList.add('visible'), 1200 + i * 2000);
        });
      }, 4000);
    }

    // Slide 5 (index 4): Pipeline phases
    if (index === 4) {
      slide.querySelectorAll('.pipeline-phase').forEach((phase, i) => {
        setTimeout(() => phase.classList.add('visible'), 200 + i * 200);
      });
    }

    // Slide 6 (index 5): Agent loop nodes + Docker containers
    if (index === 5) {
      slide.querySelectorAll('.loop-node').forEach((node, i) => {
        setTimeout(() => node.classList.add('visible'), 200 + i * 200);
      });
      const repeat = slide.querySelector('.loop-repeat');
      if (repeat) {
        setTimeout(() => repeat.classList.add('visible'), 1200);
      }
      slide.querySelectorAll('.docker-container').forEach((c, i) => {
        setTimeout(() => c.classList.add('visible'), 400 + i * 150);
      });
    }

    // Slide 7 (index 6): Temporal timeline
    if (index === 6) {
      slide.querySelectorAll('.timeline-event').forEach((ev, i) => {
        setTimeout(() => ev.classList.add('visible'), 300 + i * 200);
      });
    }

    // Slide 8 (index 7): Dashboard rows
    if (index === 7) {
      slide.querySelectorAll('.dash-row:not(.header)').forEach((row, i) => {
        setTimeout(() => row.classList.add('visible'), 300 + i * 200);
      });
    }

    // Slide 9 (index 8): Severity items
    if (index === 8) {
      slide.querySelectorAll('.severity-item').forEach((item, i) => {
        setTimeout(() => item.classList.add('visible'), 200 + i * 150);
      });
    }
  }

  // Trigger animations for first slide
  triggerSlideAnimations(0);

  // ========================================
  // AUDIO NARRATION SYSTEM
  // ========================================

  const audioToggle = document.getElementById('audio-toggle');
  const volumeSlider = document.getElementById('volume-slider');
  const audioProgressBar = document.getElementById('audio-progress-bar');

  let audioEnabled = true;
  let audioVolume = 0.8;
  let currentAudio = null;
  let audioProgressInterval = null;
  let slideAudioCache = {};

  function preloadSlideAudio(slideIndex) {
    const slideNum = slideIndex + 1;
    const paddedNum = slideNum.toString().padStart(2, '0');
    const base = window.__BASE__ || '/';
    const audioUrl = `${base}presentation-audio/slide-${paddedNum}.mp3`;

    const audio = new Audio();
    audio.preload = 'auto';
    audio.src = audioUrl;
    audio.volume = audioVolume;
    audio.addEventListener('error', () => {
      delete slideAudioCache[slideIndex];
    });
    audio.addEventListener('canplaythrough', () => {
      slideAudioCache[slideIndex] = audio;
    }, { once: true });
    slideAudioCache[slideIndex] = audio;
  }

  function preloadAllAudio() {
    Object.values(slideAudioCache).forEach(a => { a.pause(); a.src = ''; });
    slideAudioCache = {};
    for (let i = 0; i < totalSlides; i++) {
      preloadSlideAudio(i);
    }
  }

  preloadAllAudio();

  const FADE_DURATION = 600;
  const FADE_STEPS = 30;

  function fadeOutAudio(audio) {
    return new Promise((resolve) => {
      const startVol = audio.volume;
      if (startVol === 0 || audio.paused) { resolve(); return; }
      const step = startVol / FADE_STEPS;
      const interval = FADE_DURATION / FADE_STEPS;
      const timer = setInterval(() => {
        const newVol = Math.max(0, audio.volume - step);
        audio.volume = newVol;
        if (newVol <= 0.01) {
          clearInterval(timer);
          audio.pause();
          audio.volume = startVol;
          resolve();
        }
      }, interval);
    });
  }

  function fadeInAudio(audio, targetVol) {
    audio.volume = 0;
    audio.play().catch(() => {
      console.log('Audio autoplay blocked. Click the speaker icon to enable.');
    });
    const step = targetVol / FADE_STEPS;
    const interval = FADE_DURATION / FADE_STEPS;
    const timer = setInterval(() => {
      const newVol = Math.min(targetVol, audio.volume + step);
      audio.volume = newVol;
      if (newVol >= targetVol - 0.01) {
        audio.volume = targetVol;
        clearInterval(timer);
      }
    }, interval);
  }

  function stopCurrentAudio() {
    if (currentAudio) {
      const audio = currentAudio;
      const startVol = audio.volume;
      const step = startVol / 15;
      const timer = setInterval(() => {
        const newVol = Math.max(0, audio.volume - step);
        audio.volume = newVol;
        if (newVol <= 0.01) {
          clearInterval(timer);
          audio.pause();
          audio.currentTime = 0;
          audio.volume = startVol;
        }
      }, 20);
      currentAudio = null;
    }
    if (audioProgressInterval) {
      clearInterval(audioProgressInterval);
      audioProgressInterval = null;
    }
    audioProgressBar.style.width = '0%';
  }

  let pendingAudioTimer = null;

  function playSlideAudio(slideIndex) {
    if (pendingAudioTimer) { clearTimeout(pendingAudioTimer); pendingAudioTimer = null; }
    if (!audioEnabled) { stopCurrentAudio(); return; }

    const nextAudio = slideAudioCache[slideIndex];
    if (!nextAudio) { stopCurrentAudio(); return; }

    if (currentAudio && !currentAudio.paused) {
      const prevAudio = currentAudio;
      currentAudio = null;
      if (audioProgressInterval) { clearInterval(audioProgressInterval); audioProgressInterval = null; }

      fadeOutAudio(prevAudio).then(() => {
        prevAudio.currentTime = 0;
        pendingAudioTimer = window.setTimeout(() => {
          pendingAudioTimer = null;
          if (!currentAudio || currentAudio.paused) {
            startNewAudio(nextAudio, slideIndex);
          }
        }, 1000);
      });
    } else {
      Object.values(slideAudioCache).forEach(a => {
        if (a !== nextAudio && !a.paused) { a.pause(); a.currentTime = 0; }
      });
      stopCurrentAudio();
      pendingAudioTimer = window.setTimeout(() => {
        pendingAudioTimer = null;
        startNewAudio(nextAudio, slideIndex);
      }, 1200);
    }
  }

  function startNewAudio(audio, slideIndex) {
    if (!audioEnabled) return;
    audio.currentTime = 0;
    currentAudio = audio;
    fadeInAudio(audio, audioVolume);

    audioProgressInterval = window.setInterval(() => {
      if (audio.duration && !audio.paused) {
        const pct = (audio.currentTime / audio.duration) * 100;
        audioProgressBar.style.width = `${pct}%`;
      }
    }, 200);

    audio.addEventListener('ended', () => {
      audioProgressBar.style.width = '100%';
      setTimeout(() => { audioProgressBar.style.width = '0%'; }, 500);
      if (audioProgressInterval) clearInterval(audioProgressInterval);
    }, { once: true });

    // Auto-advance when narration ends, or fade out music on last slide
    audio.addEventListener('ended', () => {
      if (audioEnabled && slideIndex < totalSlides - 1) {
        setTimeout(() => {
          goToSlide(slideIndex + 1, 'next');
        }, 1200);
      } else if (slideIndex === totalSlides - 1) {
        // Last slide — fade out background music
        fadeOutBgMusic();
      }
    }, { once: true });
  }

  // Toggle narration mute
  audioToggle.addEventListener('click', () => {
    audioEnabled = !audioEnabled;
    audioToggle.classList.toggle('muted', !audioEnabled);
    if (!audioEnabled) {
      stopCurrentAudio();
    } else {
      playSlideAudio(currentSlide);
    }
  });

  // Narration volume control
  volumeSlider.addEventListener('input', () => {
    audioVolume = parseInt(volumeSlider.value) / 100;
    if (currentAudio) { currentAudio.volume = audioVolume; }
    if (audioVolume === 0) {
      audioToggle.classList.add('muted');
      audioEnabled = false;
    } else if (!audioEnabled) {
      audioEnabled = true;
      audioToggle.classList.remove('muted');
    }
  });

  // Background music controls
  const musicToggle = document.getElementById('music-toggle');
  const musicVolumeSlider = document.getElementById('music-volume-slider');
  let bgMusicEnabled = true;
  let bgMusicVolume = 0.06; // ducked level during narration

  musicToggle.addEventListener('click', () => {
    bgMusicEnabled = !bgMusicEnabled;
    musicToggle.classList.toggle('muted', !bgMusicEnabled);
    if (bgMusicStarted && bgMusic) {
      bgMusic.muted = !bgMusicEnabled;
    }
  });

  musicVolumeSlider.addEventListener('input', () => {
    const val = parseInt(musicVolumeSlider.value) / 100;
    bgMusicVolume = val * 0.12; // scale: slider 100% = 0.12 max volume
    if (bgMusicStarted && bgMusic && !bgMusic.muted) {
      bgMusic.volume = bgMusicVolume;
    }
    if (val === 0) {
      musicToggle.classList.add('muted');
      bgMusicEnabled = false;
      if (bgMusicStarted && bgMusic) { bgMusic.muted = true; }
    } else if (!bgMusicEnabled) {
      bgMusicEnabled = true;
      musicToggle.classList.remove('muted');
      if (bgMusicStarted && bgMusic) { bgMusic.muted = false; }
    }
  });

  // Keyboard shortcuts: 'A' for narration, 'M' for music
  document.addEventListener('keydown', (e) => {
    if (e.key === 'a' || e.key === 'A') { audioToggle.click(); }
    if (e.key === 'm' || e.key === 'M') { musicToggle.click(); }
  });

  // Export for goToSlide
  window.__playSlideAudio = playSlideAudio;

  // ========================================
  // BACKGROUND MUSIC
  // ========================================

  const bgMusic = new Audio((window.__BASE__ || '/') + 'presentation-audio/bg-music.mp3');
  bgMusic.loop = true;
  bgMusic.volume = 0;
  let bgMusicStarted = false;

  function fadeBgMusic(targetVol, durationMs, callback) {
    const startVol = bgMusic.volume;
    const diff = targetVol - startVol;
    const steps = Math.max(1, Math.round(durationMs / 30));
    let step = 0;
    const interval = setInterval(() => {
      step++;
      bgMusic.volume = Math.max(0, Math.min(1, startVol + diff * (step / steps)));
      if (step >= steps) {
        clearInterval(interval);
        bgMusic.volume = Math.max(0, Math.min(1, targetVol));
        if (callback) callback();
      }
    }, 30);
  }

  function startBgMusic() {
    if (bgMusicStarted) return;
    bgMusicStarted = true;
    bgMusic.play().catch(() => {});
    // Fade in to intro volume
    fadeBgMusic(0.5, 2000);
  }

  function duckBgMusic() {
    // Lower music so narration is clear
    fadeBgMusic(0.06, 2000);
  }

  function fadeOutBgMusic() {
    // End of presentation — fade to silence
    setTimeout(() => {
      fadeBgMusic(0, 3000, () => {
        bgMusic.pause();
      });
    }, 5000);
  }

  // ========================================
  // PLAY OVERLAY
  // ========================================

  const playOverlay = document.getElementById('play-overlay');
  const playOverlayBtn = document.getElementById('play-overlay-btn');

  function beginPresentation() {
    playOverlay.classList.add('hidden');
    startBgMusic();
    // Duck after a beat so user hears the intro music briefly
    setTimeout(() => { duckBgMusic(); }, 1500);
    playSlideAudio(0);
  }

  // Attempt autoplay on page load — hide overlay if browser allows it
  (function attemptAutoplay() {
    const testAudio = new Audio((window.__BASE__ || '/') + 'presentation-audio/bg-music.mp3');
    testAudio.volume = 0;
    const playPromise = testAudio.play();
    if (playPromise !== undefined) {
      playPromise.then(() => {
        // Autoplay allowed — stop test audio and start for real
        testAudio.pause();
        testAudio.src = '';
        beginPresentation();
      }).catch(() => {
        // Autoplay blocked — show overlay as fallback
        testAudio.src = '';
        playOverlay.classList.remove('hidden');
      });
    }
  })();

  playOverlayBtn.addEventListener('click', () => {
    beginPresentation();
  });

  document.addEventListener('keydown', function startOnKey(e) {
    if (!playOverlay.classList.contains('hidden') && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      beginPresentation();
      document.removeEventListener('keydown', startOnKey);
    }
  });
