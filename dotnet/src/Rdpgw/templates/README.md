# RDP Gateway Web Interface Templates

This directory contains the customizable web interface templates for RDP Gateway.

## Files

### `index.html`
The main HTML template for the web interface. This file uses Go template syntax and can be customized to match your organization's branding.

**Template Variables Available:**
- `{{.Title}}` - Page title
- `{{.Logo}}` - Header logo text
- `{{.PageTitle}}` - Main page heading
- `{{.SelectServerMessage}}` - Default button text
- `{{.PreparingMessage}}` - Loading message
- `{{.AutoLaunchMessage}}` - Auto-launch notice text

### `style.css`
The CSS stylesheet for the web interface. Modify this file to customize:
- Colors and branding
- Layout and spacing
- Fonts and typography
- Responsive behavior

### `app.js`
The JavaScript file containing the web interface logic. This includes:
- Server list loading and rendering
- User authentication display
- **Automatic RDP client launching** (multiple methods)
- File download fallback
- Progress animations

### `config-example.json`
Example configuration structure showing available customization options. These values are set as defaults in the code but can be integrated with your main configuration system.

## Auto-Launch Functionality

The interface automatically attempts to launch RDP clients using **actual RDP file content**:

### How It Works:
1. **Fetches RDP Content**: Gets the complete RDP file configuration from `/api/rdp-content`
2. **Creates Data URL**: Converts RDP content to a downloadable blob
3. **Platform-Specific Launch**:
   - **Windows**: Downloads .rdp file which auto-opens with mstsc
   - **macOS**: Downloads .rdp file which auto-opens with Microsoft Remote Desktop
   - **Universal**: Creates temporary download that browsers handle appropriately

### Technical Implementation:
- **`/api/rdp-content`** endpoint generates actual RDP file content with proper tokens
- **Data URLs** created from RDP content for browser download
- **Automatic file association** triggers RDP client launch
- **Graceful fallbacks** ensure users always get the RDP file

## Customization

To customize the interface:

1. **Copy this templates directory** to your preferred location
2. **Set the templates path** in your RDP Gateway configuration
3. **Edit the files** to match your branding requirements
4. **Restart RDP Gateway** to load the new templates

If template files are missing, the system automatically falls back to embedded templates to ensure the interface remains functional.

## API Endpoints

The web interface uses these authenticated API endpoints:

- **`/api/hosts`** - Returns available servers for the user (JSON)
- **`/api/user`** - Returns current user information (JSON)
- **`/api/rdp-content`** - Returns RDP file content as text for auto-launch
- **`/connect`** - Downloads RDP file (traditional endpoint)

## Static File Serving

The following URLs serve static files:
- `/static/style.css` - CSS stylesheet
- `/static/app.js` - JavaScript application

These files are served without authentication requirements for better performance.

## Browser Compatibility

The interface supports:
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile responsive design
- Protocol handlers for RDP client launching
- Graceful fallbacks for unsupported features

## Security Considerations

- Template files are served from the server filesystem
- Static files include cache headers for performance
- User authentication is required for the main interface
- API endpoints validate authentication before serving data