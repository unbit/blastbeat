#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

	SPDY parser is different from the HTTP one
	The parsing is done at connection-level and each STREAM ID
	is mapped to a session

	When a full frame is received it is mapped to the relevant STREAM ID (if available)

*/

const unsigned char spdy_dictionary[] = {
	0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,   //\ - - - - o p t i
	0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,   //\ o n s - - - - h
	0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,   //\ e a d - - - - p
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,   //\ o s t - - - - p
	0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,   //\ u t - - - - d e
	0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,   //\ l e t e - - - -
	0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,   //\ t r a c e - - -
	0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,   //\ - a c c e p t -
	0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,   //\ - - - a c c e p
	0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   //\ t - c h a r s e
	0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,   //\ t - - - - a c c
	0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   //\ e p t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,   //\ d i n g - - - -
	0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,   //\ a c c e p t - l
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,   //\ a n g u a g e -
	0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,   //\ - - - a c c e p
	0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,   //\ t - r a n g e s
	0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,   //\ - - - - a g e -
	0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,   //\ - - - a l l o w
	0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,   //\ - - - - a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,   //\ o r i z a t i o
	0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,   //\ n - - - - c a c
	0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,   //\ h e - c o n t r
	0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,   //\ o l - - - - c o
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,   //\ n n e c t i o n
	0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,   //\ - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,   //\ e n t - b a s e
	0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,   //\ - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   //\ e n t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,   //\ d i n g - - - -
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,   //\ c o n t e n t -
	0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,   //\ l a n g u a g e
	0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,   //\ - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,   //\ e n t - l e n g
	0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,   //\ t h - - - - c o
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,   //\ n t e n t - l o
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,   //\ c a t i o n - -
	0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   //\ - - c o n t e n
	0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,   //\ t - m d 5 - - -
	0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,   //\ - c o n t e n t
	0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,   //\ - r a n g e - -
	0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   //\ - - c o n t e n
	0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,   //\ t - t y p e - -
	0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,   //\ - - d a t e - -
	0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,   //\ - - e t a g - -
	0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,   //\ - - e x p e c t
	0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,   //\ - - - - e x p i
	0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,   //\ r e s - - - - f
	0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,   //\ r o m - - - - h
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,   //\ o s t - - - - i
	0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,   //\ f - m a t c h -
	0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,   //\ - - - i f - m o
	0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,   //\ d i f i e d - s
	0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,   //\ i n c e - - - -
	0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,   //\ i f - n o n e -
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,   //\ m a t c h - - -
	0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,   //\ - i f - r a n g
	0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,   //\ e - - - - i f -
	0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,   //\ u n m o d i f i
	0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,   //\ e d - s i n c e
	0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,   //\ - - - - l a s t
	0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,   //\ - m o d i f i e
	0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,   //\ d - - - - l o c
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,   //\ a t i o n - - -
	0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,   //\ - m a x - f o r
	0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,   //\ w a r d s - - -
	0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,   //\ - p r a g m a -
	0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,   //\ - - - p r o x y
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,   //\ - a u t h e n t
	0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,   //\ i c a t e - - -
	0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,   //\ - p r o x y - a
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,   //\ u t h o r i z a
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,   //\ t i o n - - - -
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,   //\ r a n g e - - -
	0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,   //\ - r e f e r e r
	0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,   //\ - - - - r e t r
	0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,   //\ y - a f t e r -
	0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,   //\ - - - s e r v e
	0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,   //\ r - - - - t e -
	0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,   //\ - - - t r a i l
	0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,   //\ e r - - - - t r
	0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,   //\ a n s f e r - e
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,   //\ n c o d i n g -
	0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,   //\ - - - u p g r a
	0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,   //\ d e - - - - u s
	0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,   //\ e r - a g e n t
	0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,   //\ - - - - v a r y
	0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,   //\ - - - - v i a -
	0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,   //\ - - - w a r n i
	0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,   //\ n g - - - - w w
	0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,   //\ w - a u t h e n
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,   //\ t i c a t e - -
	0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,   //\ - - m e t h o d
	0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,   //\ - - - - g e t -
	0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,   //\ - - - s t a t u
	0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,   //\ s - - - - 2 0 0
	0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,   //\ - O K - - - - v
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,   //\ e r s i o n - -
	0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,   //\ - - H T T P - 1
	0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,   //\ - 1 - - - - u r
	0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,   //\ l - - - - p u b
	0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,   //\ l i c - - - - s
	0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,   //\ e t - c o o k i
	0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,   //\ e - - - - k e e
	0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,   //\ p - a l i v e -
	0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,   //\ - - - o r i g i
	0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,   //\ n 1 0 0 1 0 1 2
	0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,   //\ 0 1 2 0 2 2 0 5
	0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,   //\ 2 0 6 3 0 0 3 0
	0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,   //\ 2 3 0 3 3 0 4 3
	0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,   //\ 0 5 3 0 6 3 0 7
	0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,   //\ 4 0 2 4 0 5 4 0
	0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,   //\ 6 4 0 7 4 0 8 4
	0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,   //\ 0 9 4 1 0 4 1 1
	0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,   //\ 4 1 2 4 1 3 4 1
	0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,   //\ 4 4 1 5 4 1 6 4
	0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,   //\ 1 7 5 0 2 5 0 4
	0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,   //\ 5 0 5 2 0 3 - N
	0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,   //\ o n - A u t h o
	0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,   //\ r i t a t i v e
	0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,   //\ - I n f o r m a
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,   //\ t i o n 2 0 4 -
	0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,   //\ N o - C o n t e
	0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,   //\ n t 3 0 1 - M o
	0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,   //\ v e d - P e r m
	0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,   //\ a n e n t l y 4
	0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,   //\ 0 0 - B a d - R
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,   //\ e q u e s t 4 0
	0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,   //\ 1 - U n a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,   //\ o r i z e d 4 0
	0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,   //\ 3 - F o r b i d
	0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,   //\ d e n 4 0 4 - N
	0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,   //\ o t - F o u n d
	0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,   //\ 5 0 0 - I n t e
	0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,   //\ r n a l - S e r
	0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,   //\ v e r - E r r o
	0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,   //\ r 5 0 1 - N o t
	0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,   //\ - I m p l e m e
	0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,   //\ n t e d 5 0 3 -
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,   //\ S e r v i c e -
	0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,   //\ U n a v a i l a
	0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,   //\ b l e J a n - F
	0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,   //\ e b - M a r - A
	0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,   //\ p r - M a y - J
	0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,   //\ u n - J u l - A
	0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,   //\ u g - S e p t -
	0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,   //\ O c t - N o v -
	0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,   //\ D e c - 0 0 - 0
	0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,   //\ 0 - 0 0 - M o n
	0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,   //\ - - T u e - - W
	0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,   //\ e d - - T h u -
	0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,   //\ - F r i - - S a
	0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,   //\ t - - S u n - -
	0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,   //\ G M T c h u n k
	0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,   //\ e d - t e x t -
	0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,   //\ h t m l - i m a
	0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,   //\ g e - p n g - i
	0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,   //\ m a g e - j p g
	0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,   //\ - i m a g e - g
	0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   //\ i f - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   //\ c a t i o n - x
	0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   //\ m l - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   //\ c a t i o n - x
	0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,   //\ h t m l - x m l
	0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,   //\ - t e x t - p l
	0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,   //\ a i n - t e x t
	0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,   //\ - j a v a s c r
	0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,   //\ i p t - p u b l
	0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,   //\ i c p r i v a t
	0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,   //\ e m a x - a g e
	0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,   //\ - g z i p - d e
	0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,   //\ f l a t e - s d
	0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   //\ c h c h a r s e
	0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,   //\ t - u t f - 8 c
	0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,   //\ h a r s e t - i
	0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,   //\ s o - 8 8 5 9 -
	0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,   //\ 1 - u t f - - -
	0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e          //\ - e n q - 0 -
};

int bb_spdy_func(struct bb_connection *bbc, char *buf, size_t len) {
        // remember: in SPDY mode, multiple sessions are allowed
        return bb_manage_spdy(bbc, buf, len);
}


void bb_ssl_info_cb(SSL const *ssl, int where, int ret) {
        if (where & SSL_CB_HANDSHAKE_DONE) {
#ifdef OPENSSL_NPN_UNSUPPORTED
                const unsigned char * proto = NULL;
                unsigned len = 0;
                SSL_get0_next_proto_negotiated(ssl, &proto, &len);
                if (len == 6 && !memcmp(proto, "spdy/3", 6)) {
                        struct bb_connection *bbc = SSL_get_ex_data(ssl, blastbeat.ssl_index);
                        // in the future it could be the version number instead of boolean
                        bbc->spdy = 3;
                        bbc->spdy_z_in.zalloc = Z_NULL;
                        bbc->spdy_z_in.zfree = Z_NULL;
                        bbc->spdy_z_in.opaque = Z_NULL;
                        if (inflateInit(&bbc->spdy_z_in) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
                        bbc->spdy_z_out.zalloc = Z_NULL;
                        bbc->spdy_z_out.zfree = Z_NULL;
                        bbc->spdy_z_out.opaque = Z_NULL;
                        if (deflateInit(&bbc->spdy_z_out, Z_DEFAULT_COMPRESSION) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
                        if (deflateSetDictionary(&bbc->spdy_z_out, (Bytef *) spdy_dictionary, sizeof(spdy_dictionary)) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
			// set the parser hook
			bbc->func = bb_spdy_func;
                }
#else
#warning OLD OpenSSL detected, SPDY support will not be enabled
#endif
                if (ssl->s3) {
                        ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
                }
        }
}

static int bb_spdy_pass_body(struct bb_connection *bbc) {
	bbc->spdy_stream_id = ntohl(bbc->spdy_stream_id);
	if (bbc->spdy_stream_id == 0) return -1;
	// find the stream
	struct bb_session *bbs = bbc->sessions_head;
	while(bbs) {
		if (bbs->stream_id == bbc->spdy_stream_id) {
			goto found;
		}
		bbs = bbs->next;
	}
	return -1;
found:
	if (!bbs->dealer) {
	  fprintf(stdout,"SPDY - No config for vhost");
	  return -1;
	}
	bb_zmq_send_msg(bbs->dealer, bbs, (char *) &bbs->uuid_part1, BB_UUID_LEN, "body", 4, bbc->spdy_body_buf, bbc->spdy_length);
	if (bbc->spdy_flags == 0x01) {
		bb_zmq_send_msg(bbs->dealer, bbs, (char *) &bbs->uuid_part1, BB_UUID_LEN, "body", 4, "", 0);
	}
	return 0;

}

static int bb_spdy_uwsgi(struct bb_session *bbs, char *ptr, uint32_t hlen) {

        // allocate the first chunk (leaving space for 4 bytes uwsgi header)
        bbs->request.uwsgi_buf = bb_alloc(4096);
        if (!bbs->request.uwsgi_buf) {
                bb_error("malloc()");
                return -1;
        }
        bbs->request.uwsgi_len = 4096;
        bbs->request.uwsgi_pos = 4;

	if (add_uwsgi_item(bbs, "SCRIPT_NAME", 11, "", 0, 0)) return -1;

	uint32_t i,klen,vlen;

	char *port = NULL;

	char *method = NULL;
	size_t method_len = 0;
	char *uri = NULL;
	size_t uri_len = 0;

	for(i=0;i<hlen;i++) {
                memcpy(&klen, ptr, 4);
                klen = ntohl(klen); ptr+=4;

		char *key = ptr;
                ptr += klen;

                memcpy(&vlen, ptr, 4);
                vlen = ntohl(vlen); ptr+=4;
		char *val = ptr;
                ptr += vlen;
		if (!bb_strcmp(key, klen, ":method", 7)) {
			if (add_uwsgi_item(bbs, "REQUEST_METHOD", 14, val, vlen, 0)) return -1;
			method = val; method_len = vlen;
		}
		else if (!bb_strcmp(key, klen, ":version", 8)) {
			if (add_uwsgi_item(bbs, "SERVER_PROTOCOL", 15, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, ":scheme", 7)) {
			if (add_uwsgi_item(bbs, "HTTP_SCHEME", 11, val, vlen, 0)) return -1;
			if (add_uwsgi_item(bbs, "SERVER_SCHEME", 13, val, vlen, 0)) return -1;
			if (!bb_strcmp(val, vlen, "https", 5)) {
				if (add_uwsgi_item(bbs, "HTTPS", 5, "on", 2, 0)) return -1;
			}
		}
		else if (!bb_strcmp(key, klen, ":host", 5)) {
			if (bb_set_dealer(bbs, val, vlen)) {
			  fprintf(stdout,"No config for specified vhost[%*s]",vlen,val);
				return -1;
			}
			if (add_uwsgi_item(bbs, "HTTP_HOST", 9, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "content-type", 12)) {
			 if (add_uwsgi_item(bbs, "CONTENT_TYPE", 12, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "content-length", 14)) {
			 if (add_uwsgi_item(bbs, "CONTENT_LENGTH", 14, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, ":path", 5)) {
        		char *query_string = memchr(val, '?', vlen);
        		if (query_string) {
                		if (add_uwsgi_item(bbs, "PATH_INFO", 9, val, query_string-val, 0)) return -1;
                		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, query_string+1, (val+vlen)-(query_string+1), 0)) return -1;
        		}
        		else {
                		if (add_uwsgi_item(bbs, "PATH_INFO", 9, val, vlen, 0)) return -1;
                		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, "", 0, 0)) return -1;
        		}
			uri = val; uri_len = vlen;
		}
        	// add HTTP_ headers
		else {
			if (add_uwsgi_item(bbs, key, klen, val, vlen, 1)) return -1;
		}

        }

	if (!bbs->dealer) {
    fprintf(stdout,"SPDY - No config for specified vhost\n");
	  return -1;
	}

	// check for mountpoint...
        // check for socket.io
        if (!bb_startswith(uri, uri_len, "/socket.io/1/", 13)) {
                if (bb_manage_socketio(bbs, method, method_len, uri, uri_len)) {
                        return -1;
                }
		goto msg;
        }

	// Ok check for cache here
	// ok now check if the virtualhost as a cache store associated
        if (bbs->vhost->cache_size > 0 && !bb_stricmp(method, method_len, "GET", 3)) {
                int ret = bb_manage_cache(bbs, uri, uri_len);
                if (ret == BLASTBEAT_CACHE_FOUND) return 0;
                if (ret == BLASTBEAT_CACHE_ERROR) return -1;
        }

msg:
	port = strchr(bbs->vhost->name, ':');

        if (port) {
               	if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, port-(bbs->vhost->name), 0)) return -1;
               	if (add_uwsgi_item(bbs, "SERVER_PORT", 11, port+1, (bbs->vhost->name + bbs->vhost->len) - (port+1), 0)) return -1;
        }
        else {
               	if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, bbs->vhost->len, 0)) return -1;
               	if (add_uwsgi_item(bbs, "SERVER_PORT", 11, "80", 2, 0)) return -1;
        }

	if (bbs->connection) {
                if (add_uwsgi_item(bbs, "REMOTE_ADDR", 11, bbs->connection->addr_str, bbs->connection->addr_str_len, 0))
                        return -1;
                if (add_uwsgi_item(bbs, "REMOTE_PORT", 11, bbs->connection->addr_port, bbs->connection->addr_port_len, 0))
                        return -1;
        }

        // mod_spdy compatibility
        add_uwsgi_item(bbs, "SPDY_VERSION", 12, "3", 1, 0);

        // set uwsgi header
        uint16_t pktsize = bbs->request.uwsgi_pos;
        bbs->request.uwsgi_buf[0] = 0;
        bbs->request.uwsgi_buf[1] = (uint8_t) (pktsize & 0xff);
        bbs->request.uwsgi_buf[2] = (uint8_t) ((pktsize >> 8) & 0xff);
        bbs->request.uwsgi_buf[3] = 0;

        return 0;
}


static char *bb_spdy_deflate(z_stream *z, char *buf, size_t len, size_t *dlen) {
	// calculate the amount of bytes needed for output (+30 should be enough)
	// this memory will be freed by the writequeue engine
	char *dbuf = bb_alloc(len+30);
	if (!dbuf) {
		bb_error("malloc()");
		return NULL;
	}
        z->avail_in = len;
        z->next_in = (Bytef *) buf;
        z->avail_out = len+30;
        z->next_out = (Bytef *) dbuf;

        if (deflate(z, Z_SYNC_FLUSH) != Z_OK) {
		return NULL;
	}
	*dlen = (char*) z->next_out - dbuf;

	return dbuf;
}

int bb_spdy_push_headers(struct bb_session *bbs) {
        int i;
	// connection is required for correct stream numbering
	struct bb_connection *bbc = bbs->connection;
        // calculate the destination buffer size
        // zzzzzzzzzzzzzzzzzzzzZZZZXXXXstatusXXXXyyyXXXXversionXXXXyyyyyyyy
        // 1v02FLenStrmAtsiPsNvpr
        // 0123456789012345678901 = 22 bytes long
        // 22 bytes + 18 hdr1 + 24 hdr2 = 64 bytes long
        //
        // transform all of the headers keys to lowercase
        size_t spdy_len = 22+18+24; // SYN_STREAM frame + 2 headers
        for(i=0;i<bbs->response.headers_count;i++) {
                spdy_len += 4 + bbs->response.headers[i].keylen + 4 + bbs->response.headers[i].vallen;
                size_t j;
                for(j=0;j<bbs->response.headers[i].keylen;j++) {
                        bbs->response.headers[i].key[j] = tolower((int) bbs->response.headers[i].key[j]);
                }
        }

	// will be freed below after a partial copy to the writequeue
        char *buf = bb_alloc(spdy_len);
        if (!buf) {
                bb_error("malloc()");
                return -1;
        }


        // SYN_STREAM
        buf[0] = 0x80; // SYN
        buf[1] = 0x03; // SPDY Version
        buf[2] = 0x00;
        buf[3] = 0x01; // Frame type (1=SYN_STREAM)

        // flags UNIDIRECTIONAL
        buf[4] = 0x02;
        // 24 bit length (later)
        // ...

        // stream_id 8-11
	// increase the push queue
        bbc->spdy_even_stream_id+=2;
	char *tmp_queue = bb_realloc(bbs->push_queue, bbs->push_queue_len, 4);
	if (!tmp_queue) {
		bb_error("realloc()");
		bb_free(buf, spdy_len);
		return -1;
	}
	bbs->push_queue = tmp_queue;
        uint32_t stream_id = htonl(bbc->spdy_even_stream_id);
        memcpy(buf+8, &stream_id, 4);
	memcpy(bbs->push_queue+bbs->push_queue_len, &stream_id, 4);
	bbs->push_queue_len+=4;


	// Associated-To-Stream-ID bytes 12-15
        stream_id = htonl(bbs->stream_id);
        memcpy(buf+12, &stream_id, 4);

        // bytes 16-19
        buf[16]=0x03; // priority
        buf[17]=0x00; // slot (credentials related)

	// set the number of headers 18-21
        uint32_t hlen = htonl(bbs->response.headers_count+2);
        memcpy(buf+18, &hlen, 4);

        char *ptr = buf+22;

        // add status header
        uint32_t slen = htonl(7);
        memcpy(ptr, &slen, 4); ptr+=4;
        memcpy(ptr, ":status", 7); ptr+=7;
        // value: 200
        slen = htonl(3);
        memcpy(ptr, &slen, 4); ptr+=4;
        *ptr++ = (bbs->response.parser.status_code/100) + '0';
        *ptr++ = ((bbs->response.parser.status_code%100)/10) + '0';
        *ptr++ = ((bbs->response.parser.status_code%100)%10) + '0';

        // add version header (HTTP/1.1)
        slen = htonl(8);
        memcpy(ptr, &slen, 4); ptr+=4;
        memcpy(ptr, ":version", 8); ptr+=8;
        // value: protocol
        slen = htonl(8);
        char proto[9];
        if (snprintf(proto, 9, "HTTP/%d.%d", bbs->response.parser.http_major, bbs->response.parser.http_minor) != 8) {
                return -1;
        }
        memcpy(ptr, &slen, 4); ptr+=4;
        memcpy(ptr, proto, 8); ptr+=8;

        // generate spdy headers from respons headers
        for(i=0;i<bbs->response.headers_count;i++) {
                slen = htonl(bbs->response.headers[i].keylen);
                memcpy(ptr, &slen, 4); ptr += 4;
                memcpy(ptr, bbs->response.headers[i].key, bbs->response.headers[i].keylen);
                ptr += bbs->response.headers[i].keylen;
                slen = htonl(bbs->response.headers[i].vallen);
                memcpy(ptr, &slen, 4); ptr += 4;
                memcpy(ptr, bbs->response.headers[i].value, bbs->response.headers[i].vallen);
                ptr += bbs->response.headers[i].vallen;
        }

        size_t ch_len = 0;
        char *compresses_headers = bb_spdy_deflate(&bbc->spdy_z_out, buf+18, spdy_len-18, &ch_len);
        if (!compresses_headers) {
                return -1;
        }

        // spec say 10 bytes (for the streamids & pri/slot) + length
        uint32_t l = htonl(10 + ch_len);
        void *ll = &l;
        memcpy(buf+5, ll+1, 3);

        if (bb_wq_push_copy(bbs, buf, 18, BB_WQ_FREE)) {
		bb_free(buf, spdy_len);
                return -1;
        }

	bb_free(buf, spdy_len);
        if (bb_wq_push_copy(bbs, compresses_headers, ch_len, BB_WQ_FREE)) {
		bb_free(compresses_headers, (spdy_len-18)+30);
                return -1;
        }
	bb_free(compresses_headers, (spdy_len-18)+30);

        return 0;
}

int bb_spdy_raw_send_headers(struct bb_session *bbs, off_t headers_count, struct bb_http_header *headers, char status[3], char protocol[8], int lower) {
	int i;
	// calculate the destination buffer size
	// zzzzzzzzzzzzZZZZXXXXstatusXXXXyyyXXXXversionXXXXyyyyyyyy
	// 1v02FLenStrmNvpr
	// 0123456789012345 = 16 bytes long
	// 16 bytes + 18 hdr1 + 24 hdr2 = 56
	//
	// transform all of the headers keys to lowercase
	size_t spdy_len = 16+18+24; // SYN_REPLY frame + 2 headers
	for(i=0;i<headers_count;i++) {
		spdy_len += 4 + headers[i].keylen + 4 + headers[i].vallen;
		if (!lower) continue;
		size_t j;
		for(j=0;j<headers[i].keylen;j++) {
			headers[i].key[j] = tolower((int) headers[i].key[j]);
		}
	}

	// will be freed later after a copy to the writequeue
	char *buf = bb_alloc(spdy_len);
	if (!buf) {
		bb_error("malloc()");
		return -1;
	}

	// SYN_REPLY
	buf[0] = 0x80; // SYN
	buf[1] = 0x03; // SPDY Version
	buf[2] = 0x00;
	buf[3] = 0x02; // Frame type (2=SYN_REPLY)

	// flags
	buf[4] = 0x00;
	// 24 bit length (later)
	// ...

	// stream_id bytes 8-11
	uint32_t stream_id = htonl(bbs->stream_id);
	memcpy(buf+8, &stream_id, 4);

	// set the number of headers 12-15
	uint32_t hlen = htonl(headers_count+2);
	memcpy(buf+12, &hlen, 4);

	char *ptr = buf+16;

	// add status header
	uint32_t slen = htonl(7);
	memcpy(ptr, &slen, 4); ptr+=4; // byte 20
	memcpy(ptr, ":status", 7); ptr+=7; // bytes 27
	// value: 200
	slen = htonl(3);
	memcpy(ptr, &slen, 4); ptr+=4; // bytes 31
	*ptr++ = status[0]; // bytes 35
	*ptr++ = status[1]; // bytes 36
	*ptr++ = status[2]; // bytes 37

  // add version header (HTTP/1.1)
	slen = htonl(8);
	memcpy(ptr, &slen, 4); ptr+=4; // byte 41
	memcpy(ptr, ":version", 8); ptr+=8; // bytes 49
	// value: protocol
	//slen = htonl(8);
	memcpy(ptr, &slen, 4); ptr+=4; // byte 52
	memcpy(ptr, protocol, 8); ptr+=8; // bytes

	// generate spdy headers from response headers
	for(i=0;i<headers_count;i++) {
		slen = htonl(headers[i].keylen);
		memcpy(ptr, &slen, 4); ptr += 4;
		memcpy(ptr, headers[i].key, headers[i].keylen);
		ptr += headers[i].keylen;
		slen = htonl(headers[i].vallen);
		memcpy(ptr, &slen, 4); ptr += 4;
		memcpy(ptr, headers[i].value, headers[i].vallen);
		ptr += headers[i].vallen;
	}

	size_t ch_len = 0;
	// send bytes from 12 on (nvkp)
	char *compresses_headers = bb_spdy_deflate(&bbs->connection->spdy_z_out, buf+12, spdy_len-12, &ch_len);
	if (!compresses_headers) {
		return -1;
	}

	// spec say 4 bytes (for the streamid) + length
	uint32_t l = htonl(4 + ch_len);
	void *ll = &l;
	memcpy(buf+5, ll+1, 3);

  // push first 12 bytes
	if (bb_wq_push_copy(bbs, buf, 12, BB_WQ_FREE)) {
		bb_free(buf, spdy_len);
		return -1;
	}
	bb_free(buf, spdy_len);

  // push remaining compressed data (ch_len bytes)
	if (bb_wq_push_copy(bbs, compresses_headers, ch_len, BB_WQ_FREE)) {
		bb_free(compresses_headers, (spdy_len-12)+30); // +30 bytes do to deflate
		return -1;
	}
	bb_free(compresses_headers, (spdy_len-12)+30); // +30 bytes do to deflate

	return 0;
}

static int bb_spdy_send_headers(struct bb_session *bbs, char *unused_buf, size_t len) {
	char status[3];
	status[0] = (bbs->response.parser.status_code/100) + '0';
	status[1] = ((bbs->response.parser.status_code%100)/10) + '0';
	status[2] = ((bbs->response.parser.status_code%100)%10) + '0';
	char proto[9];
        if (snprintf(proto, 9, "HTTP/%d.%d", bbs->response.parser.http_major, bbs->response.parser.http_minor) != 8) {
                return -1;
        }
	return bb_spdy_raw_send_headers(bbs, bbs->response.headers_count, bbs->response.headers, status, proto, 1);
}


static int bb_spdy_send_cache_headers(struct bb_session *bbs, struct bb_cache_item *bbci) {
	return bb_spdy_raw_send_headers(bbs, bbci->headers_count, bbci->headers, bbci->status, bbci->protocol, 1);
}

int bb_spdy_send_body(struct bb_session *bbs, char *buf, size_t len) {

	// gracefully stop if the session is already closed
	if (bbs->fin) return 0;

	// will be freed by the writequeue
	char *spdy = bb_alloc(len + 8);
	if (!spdy) {
		bb_error("malloc()");
		return -1;
	}

	// set stream_id 0-4 bytes
	if (bbs->push_queue_len > 0) {
		memcpy(spdy, bbs->push_queue+(bbs->push_queue_len-4), 4);
	}
	else {
		uint32_t stream_id = htonl(bbs->stream_id);
		memcpy(spdy, &stream_id, 4);
	}

	// set length 5 to 7 bytes
	uint32_t stream_length = htonl(len);
        void *sl = &stream_length;
        memcpy(spdy+5, sl+1, 3); // 24bit length
        memcpy(spdy + 8, buf, len); // place data at 8th byte

// figure out 4th byte
	// set flags
	if (len > 0) {
		spdy[4] = 0;
		return bb_wq_push(bbs, spdy, len+8, BB_WQ_FREE);
	}

	// end of the stream
	spdy[4] = 0x01;
	if (bb_wq_push(bbs, spdy, len+8, BB_WQ_FREE))
		return -1;

	if (bbs->push_queue_len > 0) {
		if (bbs->push_queue_len <= 4) {
			bb_free(bbs->push_queue, bbs->push_queue_len);
			bbs->push_queue = NULL;
			bbs->push_queue_len = 0;
			return 0;
		}
		char *tmp_queue = bb_realloc(bbs->push_queue, bbs->push_queue_len, -4);
		if (!tmp_queue) {
			bb_error("realloc()");
			return -1;
		}
		bbs->push_queue = tmp_queue;
		bbs->push_queue_len-=4;
		return 0;
	}

	bbs->fin = 1;
	return bb_wq_push_eos(bbs);

}

static int bb_spdy_send_cache_body(struct bb_session *bbs, struct bb_cache_item *bbci) {
	if (bb_spdy_send_body(bbs, bbci->body, bbci->body_len))
		return -1;
	// end the stream
	if (bb_spdy_send_body(bbs, "", 0))
		return -1;

	return 0;
}

int bb_spdy_send_end(struct bb_session *bbs) {
	if (bbs->fin) return 0;
	return bb_spdy_send_body(bbs, "", 0);
}

static int bb_spdy_inflate(struct bb_session *bbs, char *buf, size_t len) {

	struct bb_connection *bbc = bbs->connection;
	char *dbuf = NULL;
	size_t dbuf_len = 0;
	char zbuf[4096];
	off_t pos = 0;

	bbc->spdy_z_in.avail_in = len - 10;
	bbc->spdy_z_in.next_in = (Bytef *) buf + 10;

	while(bbc->spdy_z_in.avail_in > 0) {
		// calculate destination buffer (must be freed !!!)
		char *tmp_buf = bb_realloc(dbuf, dbuf_len, 4096);
		if (!tmp_buf) {
			bb_error("malloc()");
			return -1;
		}
		dbuf_len+=4096;
		dbuf = tmp_buf;

		bbc->spdy_z_in.avail_out = 4096;
		bbc->spdy_z_in.next_out = (Bytef *) zbuf;

		int ret = inflate(&bbc->spdy_z_in, Z_NO_FLUSH);
		if (ret == Z_NEED_DICT) {
			inflateSetDictionary(&bbc->spdy_z_in, (Bytef *) spdy_dictionary, sizeof(spdy_dictionary));
			ret = inflate(&bbc->spdy_z_in, Z_NO_FLUSH);
		}
		if (ret != Z_OK) return -1;
		size_t zlen = (char *)bbc->spdy_z_in.next_out-zbuf;
		memcpy(dbuf+pos, zbuf, zlen);
		pos+=zlen;
	}


	uint32_t hlen = 0;
	memcpy(&hlen, dbuf, 4);
	hlen = ntohl(hlen);

	// generate a uwsgi packet from spdy headers
	// TODO add a safety check on max buffer size
	int ret = 0;
	if (bb_spdy_uwsgi(bbs, dbuf+4, hlen)) ret = -1;
	// free the inflated buffer
	bb_free(dbuf, dbuf_len);
	return ret;
}

static void bb_spdy_header(struct bb_connection *bbc) {
	bbc->spdy_control = (bbc->spdy_header_buf[0] >> 7) & 0x01;
	bbc->spdy_header_buf[0] = bbc->spdy_header_buf[0] & 0x7f;
	memcpy(&bbc->spdy_version, bbc->spdy_header_buf, 2);
	bbc->spdy_version = ntohs(bbc->spdy_version);
	bbc->spdy_flags = bbc->spdy_header_buf[4];
	void *slp = &bbc->spdy_length;
	memcpy(slp+1, bbc->spdy_header_buf + 5, 3);
	bbc->spdy_length = ntohl(bbc->spdy_length);
	if (bbc->spdy_control) {
		memcpy(&bbc->spdy_type, bbc->spdy_header_buf + 2, 2);
		bbc->spdy_type = ntohs(bbc->spdy_type);
	}
	else {
		memcpy(&bbc->spdy_stream_id, bbc->spdy_header_buf, 4);
	}
}

static int bb_manage_spdy_msg(struct bb_connection *bbc) {
	char *pong;
	switch(bbc->spdy_type) {
		// new STREAM
		case 0x01:
			bbc->spdy_body_buf[0] = bbc->spdy_body_buf[0] &0x7f;
			memcpy(&bbc->spdy_stream_id, bbc->spdy_body_buf, 4);
			bbc->spdy_stream_id = ntohl(bbc->spdy_stream_id);
			struct bb_session *bbs = bb_session_new(bbc);
			if (!bbs) {
			  return -1;
			}
			// set the SPDY hooks
			bbs->send_headers = bb_spdy_send_headers;
			bbs->send_end = bb_spdy_send_end;
			bbs->send_body = bb_spdy_send_body;
			bbs->send_cache_headers = bb_spdy_send_cache_headers;
			bbs->send_cache_body = bb_spdy_send_cache_body;

			// prepare for a new request
                	bb_initialize_request(bbs);

			bbs->stream_id = bbc->spdy_stream_id;
			if (bb_spdy_inflate(bbs, bbc->spdy_body_buf, bbc->spdy_length)) {
				return -1;
			}
			// check for dealer as the host: header could be missing !!!
			if (!bbs->dealer) {
			  fprintf(stdout,"bb_manage_spdy_msg - no config for vhost\n");
			  return -1;
			}
			if (!bbs->request.no_uwsgi)
				bb_zmq_send_msg(bbs->dealer, bbs, (char *) &bbs->uuid_part1, BB_UUID_LEN, "uwsgi", 5, bbs->request.uwsgi_buf, bbs->request.uwsgi_pos);
			break;
		// RST
		case 0x03:
			memcpy(&bbc->spdy_stream_id, bbc->spdy_body_buf, 4);
			// ignore resets of even stream (push)
                        if ((ntohl(bbc->spdy_stream_id) % 2) == 0) break;
			fprintf(stderr,"RESET THE STREAM %d\n", ntohl(bbc->spdy_stream_id));
			// TODO scan all of the connection-related sessions and close the required one
                      	struct bb_session *active_stream = bbc->sessions_head;
			while(active_stream) {
				fprintf(stderr,"[connection %p] active SPDY stream %d\n", bbc, active_stream->stream_id);
				active_stream = active_stream->next;
			}
			break;
		// SETTINGS
		case 0x04:
			// ignore settins (for now)
			//fprintf(stderr,"SETTINGS FLAGS %d\n", ntohl(bbc->spdy_flags));
			break;
		// PING
		case 0x06:
			pong = bb_alloc(8+4);
			if (!pong) {
				bb_error("pong malloc()");
				return -1;
			}
			memcpy(pong, "\x80\x03\x00\x06\x00\x00\x00\x04", 8);
			memcpy(pong + 8, bbc->spdy_body_buf, 4);
			if (bb_wq_dumb_push(bbc, pong, 12, BB_WQ_FREE)) {
				bb_free(pong, 8+4);
                		return -1;
        		}
			break;
		// GOAWAY
		case 0x07:
			// just force connection close
			return -1;
		case 0x08: // Headers
		  // I'm pretty sure we shouldn't be getting these
		  //fprintf(stdout,"SPDY_TYPE Headers\n");
      //fprintf(stdout,"1[%x]v[%x][%x]8[%x]\n",bbc->spdy_body_buf[0],bbc->spdy_body_buf[1],bbc->spdy_body_buf[2],bbc->spdy_body_buf[3]);
      //fprintf(stdout,"F[%x]L[%x]e[%x]n[%x]\n",bbc->spdy_body_buf[4],bbc->spdy_body_buf[5],bbc->spdy_body_buf[6],bbc->spdy_body_buf[7]);
      //fprintf(stdout,"x[%x]s[%x]i[%x]d[%x]\n",bbc->spdy_body_buf[8],bbc->spdy_body_buf[9],bbc->spdy_body_buf[10],bbc->spdy_body_buf[11]);
      //fprintf(stdout,"D[%x]w[%x]d[%x]w[%x]\n",bbc->spdy_body_buf[12],bbc->spdy_body_buf[13],bbc->spdy_body_buf[14],bbc->spdy_body_buf[15]);
		  break;
		case 0x09: // window_update
		  // FIXME: implement flow control
		  //fprintf(stdout,"SPDY_TYPE window_update\n");
      //fprintf(stdout,"1[%x]v[%x][%x]9[%x]\n",bbc->spdy_body_buf[0],bbc->spdy_body_buf[1],bbc->spdy_body_buf[2],bbc->spdy_body_buf[3]);
      //fprintf(stdout,"F[%x]L[%x]e[%x]n[%x]\n",bbc->spdy_body_buf[4],bbc->spdy_body_buf[5],bbc->spdy_body_buf[6],bbc->spdy_body_buf[7]);
      //fprintf(stdout,"x[%x]s[%x]i[%x]d[%x]\n",bbc->spdy_body_buf[8],bbc->spdy_body_buf[9],bbc->spdy_body_buf[10],bbc->spdy_body_buf[11]);
      //fprintf(stdout,"D[%x]w[%x]d[%x]w[%x]\n",bbc->spdy_body_buf[12],bbc->spdy_body_buf[13],bbc->spdy_body_buf[14],bbc->spdy_body_buf[15]);
		  break;
		// 1010 is credentials
		default:
			fprintf(stderr,"UNKNOWN SPDY MESSAGE %d!!!\n", bbc->spdy_type);
			return -1;
	}
	return 0;
}

int bb_manage_spdy(struct bb_connection *bbc, char *buf, ssize_t len) {

	size_t remains = len;
	while(remains > 0) {
		switch(bbc->spdy_status) {
			// still waiting for 8 byte header
			case 0:
				// enough bytes ?
				if (remains >= (8-bbc->spdy_header_pos)) {
					memcpy(bbc->spdy_header_buf + bbc->spdy_header_pos, buf + (len- remains), (8-bbc->spdy_header_pos));
					remains -= (8-bbc->spdy_header_pos);
					// ready to receive the body
					bb_spdy_header(bbc);
					if (bbc->spdy_length > 0) {
						bbc->spdy_status = 1;
						// clear old body buffer
						if (bbc->spdy_body_buf) {
							bb_free(bbc->spdy_body_buf, bbc->spdy_length);
						}
						// create new body buffer
						bbc->spdy_body_buf = bb_alloc(bbc->spdy_length);
						break;
					}
					return -1;
				}
				memcpy(bbc->spdy_header_buf + bbc->spdy_header_pos, buf + (len - remains), remains);
				bbc->spdy_header_pos += remains;
				return 0;
			case 1:
				if (remains >= (bbc->spdy_length - bbc->spdy_body_pos)) {
					memcpy(bbc->spdy_body_buf + bbc->spdy_body_pos , buf + (len - remains), (bbc->spdy_length - bbc->spdy_body_pos));
					remains -= (bbc->spdy_length - bbc->spdy_body_pos);
					if (bbc->spdy_type == 0) {
						if (bb_spdy_pass_body(bbc)) {
							return -1;
						}
					}
					else if (bb_manage_spdy_msg(bbc)) {
					  // fix memory leak, when goaway packet is sent, we need to free the body
					  if (bbc->spdy_type == 7) {
					    bb_free(bbc->spdy_body_buf, bbc->spdy_length);
					  }
						return -1;
					}
					// reset SPDY parser
					bb_free(bbc->spdy_body_buf, bbc->spdy_length);
					bbc->spdy_body_buf = NULL;
					bbc->spdy_body_pos = 0;
					bbc->spdy_length = 0;
					bbc->spdy_status = 0;
					bbc->spdy_header_pos = 0;
					bbc->spdy_body_pos = 0;
					bbc->spdy_stream_id = 0;
					bbc->spdy_type = 0;
					break;
				}
				memcpy(bbc->spdy_body_buf + bbc->spdy_body_pos , buf + (len - remains), remains);
				bbc->spdy_body_pos += remains;
				return 0;
			default:
				return -1;
		}
	}
	return 0;
}
