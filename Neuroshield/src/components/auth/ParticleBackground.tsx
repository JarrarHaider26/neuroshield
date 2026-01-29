
'use client';

import React, { useEffect, useMemo, useState } from 'react';
import Particles, { initParticlesEngine } from '@tsparticles/react';
import { loadBasic } from '@tsparticles/basic';
import type { Container, ISourceOptions } from '@tsparticles/engine';
import { useTheme } from 'next-themes';

export function ParticleBackground() {
  const [init, setInit] = useState(false);
  const { theme } = useTheme();

  useEffect(() => {
    console.log('[ParticleBackground] useEffect: Initializing particles engine.');
    let isMounted = true;

    const initializeParticles = async () => {
      try {
        await initParticlesEngine(async (engine) => {
          console.log('[ParticleBackground] initParticlesEngine callback: Loading basic preset.');
          try {
            await loadBasic(engine);
            if (isMounted) {
              console.log('[ParticleBackground] Basic preset loaded successfully. Setting init to true.');
              setInit(true);
            }
          } catch (presetError) {
            console.error('[ParticleBackground] Error loading basic preset:', presetError);
            if (isMounted) {
              setInit(false);
            }
          }
        });
      } catch (engineError) {
        console.error('[ParticleBackground] Error initializing particles engine:', engineError);
        if (isMounted) {
          setInit(false);
        }
      }
    };

    initializeParticles();

    return () => {
      console.log('[ParticleBackground] useEffect cleanup: Component unmounted.');
      isMounted = false;
    };
  }, []);

  const particlesLoaded = async (container?: Container): Promise<void> => {
    // console.log('[ParticleBackground] Particles loaded callback. Container:', container);
  };

  const particleOptions: ISourceOptions = useMemo(
    () => ({
      autoPlay: true,
      background: {
        color: {
          value: 'transparent',
        },
      },
      fpsLimit: 60,
      interactivity: {
        events: {
          onClick: {
            enable: false,
            mode: 'push',
          },
          onHover: {
            enable: false,
            mode: 'repulse',
          },
        },
        modes: {
          push: {
            quantity: 4,
          },
          repulse: {
            distance: 100,
            duration: 0.4,
          },
        },
      },
      particles: {
        color: {
          value: theme === 'dark' ? 'hsl(var(--primary))' : 'hsl(var(--foreground))',
        },
        links: {
          color: theme === 'dark' ? 'hsl(var(--primary) / 0.4)' : 'hsl(var(--foreground) / 0.4)',
          distance: 150,
          enable: true,
          opacity: 0.3,
          width: 1,
        },
        move: {
          direction: 'none',
          enable: true,
          outModes: {
            default: 'out',
          },
          random: true,
          speed: 0.5,
          straight: false,
        },
        number: {
          density: {
            enable: true,
            area: 800,
          },
          value: 30,
        },
        opacity: {
          value: { min: 0.1, max: 0.5 },
           animation: {
            enable: true,
            speed: 0.5,
            minimumValue: 0.1,
            sync: false,
          },
        },
        shape: {
          type: 'circle',
        },
        size: {
          value: { min: 1, max: 3 },
          animation: {
            enable: true,
            speed: 2,
            minimumValue: 0.1,
            sync: false,
          },
        },
      },
      detectRetina: true,
    }),
    [theme]
  );

  if (init) {
    console.log('[ParticleBackground] Rendering Particles component.');
    return (
      <Particles
        id="tsparticles"
        particlesLoaded={particlesLoaded}
        options={particleOptions}
        className="absolute inset-0 z-0"
      />
    );
  }
  console.log('[ParticleBackground] Particles not initialized or init is false. Rendering empty fragment.');
  return <></>;
}
