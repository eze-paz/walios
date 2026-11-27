/* sdl2-demo: an SDL2 program for walios' X display. An animated background, a box that
 * follows the mouse, and every click and key printed on stdout (what tests check), plus the
 * frame rate every 120 frames. Software rendering. `sdl2-demo --version` prints the SDL version. */
#include <SDL2/SDL.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--version")) {
		SDL_version v; SDL_GetVersion(&v);
		printf("sdl2-demo 1 (SDL %d.%d.%d)\n", v.major, v.minor, v.patch);
		return 0;
	}
	if (SDL_Init(SDL_INIT_VIDEO) != 0) { fprintf(stderr, "SDL_Init: %s\n", SDL_GetError()); return 1; }
	SDL_Window *w = SDL_CreateWindow("SDL2 on walios", 60, 60, 480, 320, 0);
	if (!w) { fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError()); return 1; }
	SDL_Renderer *r = SDL_CreateRenderer(w, -1, SDL_RENDERER_SOFTWARE);
	if (!r) { fprintf(stderr, "SDL_CreateRenderer: %s\n", SDL_GetError()); return 1; }
	printf("video driver %s, software renderer\n", SDL_GetCurrentVideoDriver());
	fflush(stdout);
	int mx = 240, my = 160, frame = 0, running = 1;
	Uint32 t0 = SDL_GetTicks();
	while (running) {
		SDL_Event e;
		while (SDL_PollEvent(&e)) {
			if (e.type == SDL_QUIT) running = 0;
			else if (e.type == SDL_MOUSEMOTION) { mx = e.motion.x; my = e.motion.y; }
			else if (e.type == SDL_MOUSEBUTTONDOWN) { printf("button %d at %d %d\n", e.button.button, e.button.x, e.button.y); fflush(stdout); }
			else if (e.type == SDL_KEYDOWN) {
				printf("key %s\n", SDL_GetKeyName(e.key.keysym.sym)); fflush(stdout);
				if (e.key.keysym.sym == SDLK_ESCAPE) running = 0;
			}
		}
		for (int y = 0; y < 320; y += 8) {
			SDL_SetRenderDrawColor(r, (y + frame) & 255, 64, 160, 255);
			SDL_Rect b = { 0, y, 480, 8 };
			SDL_RenderFillRect(r, &b);
		}
		SDL_SetRenderDrawColor(r, 255, 220, 0, 255);
		SDL_Rect m = { mx - 20, my - 20, 40, 40 };
		SDL_RenderFillRect(r, &m);
		SDL_RenderPresent(r);
		frame++;
		if (frame % 120 == 0) {
			Uint32 t = SDL_GetTicks();
			printf("fps %.1f\n", 120000.0 / (t - t0 ? t - t0 : 1)); fflush(stdout);
			t0 = t;
		}
		SDL_Delay(10);
	}
	SDL_Quit();
	return 0;
}
