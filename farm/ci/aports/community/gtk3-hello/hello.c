/* gtk3-hello: a small GTK3 window for walios' X display -- a label, an entry, a check button,
 * a button and a slider. Every click, toggle and Enter in the entry is printed on stdout (what
 * tests check). `gtk3-hello --version` prints the GTK version without opening a display. */
#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

static void say(const char *what, const char *detail) { printf("%s %s\n", what, detail ? detail : ""); fflush(stdout); }
static void on_click(GtkButton *b, gpointer label) {
	static int n = 0; char buf[64];
	snprintf(buf, sizeof buf, "Clicked %d time%s", ++n, n == 1 ? "" : "s");
	gtk_label_set_text(GTK_LABEL(label), buf); say("clicked", buf);
}
static void on_toggle(GtkToggleButton *t, gpointer u) { say("toggled", gtk_toggle_button_get_active(t) ? "on" : "off"); }
static void on_activate_entry(GtkEntry *e, gpointer u) { say("entry", gtk_entry_get_text(e)); }

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "--version")) {
		printf("gtk3-hello 1 (GTK %u.%u.%u)\n", gtk_get_major_version(), gtk_get_minor_version(), gtk_get_micro_version());
		return 0;
	}
	gtk_init(&argc, &argv);
	GtkWidget *w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(w), "GTK3 on walios");
	gtk_window_set_default_size(GTK_WINDOW(w), 360, 240);
	gtk_window_move(GTK_WINDOW(w), 420, 80);
	g_signal_connect(w, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
	gtk_container_set_border_width(GTK_CONTAINER(box), 12);
	gtk_container_add(GTK_CONTAINER(w), box);
	GtkWidget *label = gtk_label_new("Hello from GTK3 in walios");
	GtkWidget *entry = gtk_entry_new();
	gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "type here, then Enter");
	GtkWidget *check = gtk_check_button_new_with_label("A check button");
	GtkWidget *scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 0, 100, 1);
	GtkWidget *button = gtk_button_new_with_label("Click me");
	g_signal_connect(button, "clicked", G_CALLBACK(on_click), label);
	g_signal_connect(check, "toggled", G_CALLBACK(on_toggle), NULL);
	g_signal_connect(entry, "activate", G_CALLBACK(on_activate_entry), NULL);
	for (GtkWidget **p = (GtkWidget *[]){ label, entry, check, scale, button, NULL }; *p; p++)
		gtk_box_pack_start(GTK_BOX(box), *p, FALSE, FALSE, 0);
	gtk_widget_show_all(w);
	say("ready", gtk_get_major_version() == 3 ? "gtk3" : "gtk");
	gtk_main();
	return 0;
}
